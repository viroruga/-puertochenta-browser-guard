import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { ResolveConfig } from "../src/Config/ResolveConfig";
import { GuardContext } from "../src/Core/GuardContext";
import { RiskEngine } from "../src/Core/RiskEngine";
import { PrototypePollutionDetector } from "../src/Detectors/PrototypePollutionDetector";
import { MaxChangesPerCheck, PrototypeMonitor } from "../src/Monitors/PrototypeMonitor";
import type { PrototypeChangeData, SecurityEvent } from "../src/Types/SecurityEvent";
import type { SecurityFinding } from "../src/Types/SecurityFinding";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

type Mutable = Record<string, unknown>;

function CreateMonitor(): {
  Monitor: PrototypeMonitor;
  Events: SecurityEvent[];
  Context: GuardContext;
} {
  const events: SecurityEvent[] = [];
  const context = new GuardContext(ResolveConfig(), window, (event) => events.push(event));
  return { Monitor: new PrototypeMonitor(context), Events: events, Context: context };
}

function Changes(events: SecurityEvent[]): PrototypeChangeData[] {
  return events.map((event) => event.Data as PrototypeChangeData);
}

describe("PrototypeMonitor", () => {
  const cleanups: (() => void)[] = [];

  afterEach(() => {
    for (const cleanup of cleanups.splice(0)) {
      cleanup();
    }
  });

  it("detecta propiedades nuevas", () => {
    const { Monitor, Events, Context } = CreateMonitor();
    Monitor.Start();
    (Object.prototype as Mutable).polluted = true;
    cleanups.push(() => delete (Object.prototype as Mutable).polluted);

    Monitor.CheckNow();
    Context.Flush();
    expect(Changes(Events)).toEqual([
      {
        Target: "Object.prototype",
        Property: "polluted",
        Change: "added",
        ValueType: "boolean",
        IsAccessor: false,
      },
    ]);
    Monitor.Stop();
  });

  it("detecta propiedades eliminadas y descriptores modificados", () => {
    const { Monitor, Events, Context } = CreateMonitor();
    Object.defineProperty(Array.prototype, "bgTemp", {
      value: 1,
      configurable: true,
      writable: true,
    });
    Monitor.Start();

    Object.defineProperty(Array.prototype, "bgTemp", {
      value: 1,
      configurable: true,
      writable: false,
    });
    Monitor.CheckNow();
    delete (Array.prototype as unknown as Mutable).bgTemp;
    Monitor.CheckNow();
    Context.Flush();

    expect(Changes(Events).map((change) => [change.Property, change.Change])).toEqual([
      ["bgTemp", "modified"],
      ["bgTemp", "removed"],
    ]);
    Monitor.Stop();
  });

  it("detecta reemplazo de funciones nativas", () => {
    const { Monitor, Events, Context } = CreateMonitor();
    const original = String.prototype.trim;
    Monitor.Start();
    String.prototype.trim = function trim(this: string): string {
      return original.call(this);
    };
    cleanups.push(() => (String.prototype.trim = original));

    Monitor.CheckNow();
    Context.Flush();
    expect(Changes(Events)[0]).toMatchObject({
      Target: "String.prototype",
      Property: "trim",
      Change: "modified",
      LooksNative: false,
      PreviousLooksNative: true,
    });
    Monitor.Stop();
  });

  it("no reporta la reversión al estado inicial", () => {
    const { Monitor, Events, Context } = CreateMonitor();
    Monitor.Start();
    (Object.prototype as Mutable).polluted = true;
    Monitor.CheckNow();
    delete (Object.prototype as Mutable).polluted;
    Monitor.CheckNow();

    const original = Array.prototype.includes;
    Array.prototype.includes = function includes(): boolean {
      return false;
    };
    Monitor.CheckNow();
    Array.prototype.includes = original;
    Monitor.CheckNow();
    Context.Flush();

    expect(Changes(Events).map((change) => [change.Property, change.Change])).toEqual([
      ["polluted", "added"],
      ["includes", "modified"],
    ]);
    Monitor.Stop();
  });

  it("reporta cada cambio una sola vez", () => {
    const { Monitor, Events, Context } = CreateMonitor();
    Monitor.Start();
    (Promise.prototype as unknown as Mutable).once = 1;
    cleanups.push(() => delete (Promise.prototype as unknown as Mutable).once);
    Monitor.CheckNow();
    Monitor.CheckNow();
    Context.Flush();
    expect(Events).toHaveLength(1);
    Monitor.Stop();
  });

  it("limita la cantidad de eventos por verificación", () => {
    const { Monitor, Events, Context } = CreateMonitor();
    Monitor.Start();
    const keys = Array.from({ length: MaxChangesPerCheck + 10 }, (_, i) => `bulk${i}`);
    for (const key of keys) {
      (Function.prototype as unknown as Mutable)[key] = 1;
    }
    cleanups.push(() => {
      for (const key of keys) {
        Reflect.deleteProperty(Function.prototype, key);
      }
    });
    Monitor.CheckNow();
    Context.Flush();
    expect(Events).toHaveLength(MaxChangesPerCheck);
    Monitor.Stop();
  });

  it("no verifica después de Stop", () => {
    const { Monitor, Events, Context } = CreateMonitor();
    Monitor.Start();
    Monitor.Stop();
    (Object.prototype as Mutable).afterStop = 1;
    cleanups.push(() => delete (Object.prototype as Mutable).afterStop);
    Monitor.CheckNow();
    Context.Flush();
    expect(Events).toHaveLength(0);
  });
});

describe("PrototypePollutionDetector", () => {
  function Evaluate(data: PrototypeChangeData): SecurityFinding | null {
    const event: SecurityEvent<PrototypeChangeData> = {
      Id: "evt-1",
      Timestamp: 1,
      Type: "prototype.changed",
      Source: "Test",
      Data: data,
    };
    return new RiskEngine({}, "info").Evaluate(
      new PrototypePollutionDetector().Analyze(event),
      event,
    );
  }

  it("Object.prototype.polluted → critical", () => {
    const finding = Evaluate({ Target: "Object.prototype", Property: "polluted", Change: "added" });
    expect(finding?.Severity).toBe("critical");
    expect(finding?.Title).toBe("Object.prototype.polluted added");
    expect(finding?.Description).toContain("prototype pollution");
  });

  it("isAdmin se detecta sin distinguir mayúsculas", () => {
    const finding = Evaluate({ Target: "Object.prototype", Property: "IsAdmin", Change: "added" });
    expect(finding?.Signals).toContain("prototype.suspicious-key");
  });

  it("un método nuevo en Array.prototype (polyfill) no es crítico → low", () => {
    const finding = Evaluate({ Target: "Array.prototype", Property: "groupBy", Change: "added" });
    expect(finding?.Severity).toBe("low");
  });

  it("reemplazo de una función nativa → medium", () => {
    const finding = Evaluate({
      Target: "String.prototype",
      Property: "trim",
      Change: "modified",
      LooksNative: false,
      PreviousLooksNative: true,
    });
    expect(finding?.Severity).toBe("medium");
    expect(finding?.Description).toContain("native implementation");
  });

  it("eliminación de una función nativa de Object.prototype → high", () => {
    const finding = Evaluate({
      Target: "Object.prototype",
      Property: "hasOwnProperty",
      Change: "removed",
      PreviousLooksNative: true,
    });
    expect(finding?.Severity).toBe("high");
  });

  it("modificación del accessor __proto__ → critical", () => {
    const finding = Evaluate({
      Target: "Object.prototype",
      Property: "__proto__",
      Change: "modified",
      ValueType: "accessor",
    });
    expect(finding?.Severity).toBe("critical");
  });
});

describe("PrototypeMonitor integrado", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    ResetGuard();
    vi.useRealTimers();
    delete (Object.prototype as Mutable).isAdmin;
  });

  it("la verificación periódica produce un hallazgo crítico", async () => {
    const guard = BrowserGuard.Start({
      Console: false,
      Integrity: { IntervalMs: 1000 },
      Monitors: {
        Fetch: false,
        Xhr: false,
        WebSocket: false,
        Dom: false,
        Csp: false,
        Runtime: false,
      },
    });
    const critical = vi.fn();
    guard.On("Critical", critical);

    (Object.prototype as Mutable).isAdmin = true;
    await vi.advanceTimersByTimeAsync(3000);
    await FlushMicrotasks();

    expect(critical).toHaveBeenCalledTimes(1);
    expect((critical.mock.calls[0]?.[0] as SecurityFinding).Title).toBe(
      "Object.prototype.isAdmin added",
    );
  });

  it("Stop detiene los timers internos", () => {
    BrowserGuard.Start({ Console: false, Monitors: { Runtime: false } });
    const before = vi.getTimerCount();
    BrowserGuard.Stop();
    expect(vi.getTimerCount()).toBeLessThan(before);
    expect(vi.getTimerCount()).toBe(0);
  });
});
