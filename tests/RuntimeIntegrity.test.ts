import { afterEach, describe, expect, it } from "vitest";
import { ResolveConfig } from "../src/Config/ResolveConfig";
import { FunctionPatch } from "../src/Core/FunctionPatch";
import { GuardContext } from "../src/Core/GuardContext";
import { RiskEngine } from "../src/Core/RiskEngine";
import { RuntimeIntegrityDetector } from "../src/Detectors/RuntimeIntegrityDetector";
import { RuntimeMonitor } from "../src/Monitors/RuntimeMonitor";
import type { RuntimeModificationData, SecurityEvent } from "../src/Types/SecurityEvent";
import type { SecurityFinding } from "../src/Types/SecurityFinding";
import { AnalyzeFunction, IsToStringTampered } from "../src/Utils/NativeFunctionUtils";

describe("NativeFunctionUtils", () => {
  it("reconoce funciones nativas", () => {
    expect(AnalyzeFunction(Math.max, { ExpectedName: "max" })).toEqual({
      LooksNative: true,
      Confidence: 1,
      Signals: [],
    });
    expect(AnalyzeFunction(Array, { ExpectedName: "Array", IsConstructor: true }).LooksNative).toBe(
      true,
    );
  });

  it("detecta funciones de usuario y arrows", () => {
    function fetch(): void {}
    const analysis = AnalyzeFunction(fetch, { ExpectedName: "fetch" });
    expect(analysis.LooksNative).toBe(false);
    expect(analysis.Signals).toContain("non-native-source");
    expect(analysis.Signals).toContain("unexpected-prototype");
    expect(AnalyzeFunction(() => 1).LooksNative).toBe(false);
  });

  it("no se deja engañar por un toString propio", () => {
    function fetch(): void {}
    fetch.toString = (): string => "function fetch() { [native code] }";
    const analysis = AnalyzeFunction(fetch, { ExpectedName: "fetch" });
    expect(analysis.LooksNative).toBe(false);
    expect(analysis.Signals).toEqual(
      expect.arrayContaining(["non-native-source", "own-tostring-override"]),
    );
  });

  it("detecta nombre inesperado", () => {
    expect(AnalyzeFunction(Math.max, { ExpectedName: "min" }).Signals).toContain("name-mismatch");
  });

  it("un Proxy sobre una función nativa parece nativo (limitación documentada)", () => {
    const proxy = new Proxy(Math.max, {});
    expect(AnalyzeFunction(proxy, { ExpectedName: "max" }).LooksNative).toBe(true);
  });

  it("valores que no son funciones", () => {
    expect(AnalyzeFunction(42)).toEqual({
      LooksNative: false,
      Confidence: 1,
      Signals: ["not-a-function"],
    });
  });

  it("detecta reemplazo de Function.prototype.toString", () => {
    const original = Function.prototype.toString;
    expect(IsToStringTampered()).toBe(false);
    Function.prototype.toString = function toString(this: unknown): string {
      return original.call(this);
    };
    try {
      expect(IsToStringTampered()).toBe(true);
      expect(AnalyzeFunction(Math.max).Signals).toContain("tostring-tampered");
    } finally {
      Function.prototype.toString = original;
    }
  });
});

describe("RuntimeMonitor", () => {
  const restorers: (() => void)[] = [];

  afterEach(() => {
    for (const restore of restorers.splice(0)) {
      restore();
    }
  });

  function Setup(): {
    Monitor: RuntimeMonitor;
    Events: SecurityEvent<RuntimeModificationData>[];
    Context: GuardContext;
  } {
    const events: SecurityEvent<RuntimeModificationData>[] = [];
    const context = new GuardContext(ResolveConfig(), window, (event) => {
      events.push(event as SecurityEvent<RuntimeModificationData>);
    });
    return { Monitor: new RuntimeMonitor(context), Events: events, Context: context };
  }

  it("el baseline solo reporta funciones que ya no parecen nativas", () => {
    const { Monitor, Events, Context } = Setup();
    Monitor.Start();
    Context.Flush();
    const targets = Events.map((event) => event.Data.Target);
    // jsdom y Node implementan en JS varias funciones que en un navegador son nativas
    // (XHR, appendChild, setTimeout...). eval y Function son nativos en ambos.
    expect(targets).not.toContain("eval");
    expect(targets).not.toContain("Function");
    expect(Events.every((event) => event.Data.Phase === "baseline")).toBe(true);
    Monitor.Stop();
  });

  it("detecta el reemplazo posterior de setTimeout", () => {
    const { Monitor, Events, Context } = Setup();
    Monitor.Start();
    Context.Flush();
    Events.length = 0;

    const original = window.setTimeout;
    window.setTimeout = function setTimeout(...args: Parameters<typeof original>) {
      return original(...args);
    } as typeof window.setTimeout;
    restorers.push(() => (window.setTimeout = original));

    Monitor.CheckNow();
    Monitor.CheckNow();
    Context.Flush();
    expect(Events).toHaveLength(1);
    expect(Events[0]?.Data).toMatchObject({
      Target: "setTimeout",
      Phase: "change",
      Analysis: { LooksNative: false },
    });
    Monitor.Stop();
  });

  it("no reporta la restauración de la función original", () => {
    const { Monitor, Events, Context } = Setup();
    const original = window.setTimeout;
    Monitor.Start();
    Context.Flush();
    Events.length = 0;

    window.setTimeout = function setTimeout(...args: Parameters<typeof original>) {
      return original(...args);
    } as typeof window.setTimeout;
    Monitor.CheckNow();
    window.setTimeout = original;
    Monitor.CheckNow();
    Context.Flush();

    expect(Events.map((event) => event.Data.Phase)).toEqual(["change"]);
    Monitor.Stop();
  });

  it("detecta funciones eliminadas", () => {
    const { Monitor, Events, Context } = Setup();
    const original = window.setInterval;
    Monitor.Start();
    Context.Flush();
    Events.length = 0;

    // @ts-expect-error -- se elimina para simular la remoción.
    window.setInterval = undefined;
    restorers.push(() => (window.setInterval = original));
    Monitor.CheckNow();
    Context.Flush();
    expect(Events[0]?.Data).toEqual({ Target: "setInterval", Phase: "removed" });
    Monitor.Stop();
  });

  it("ignora los interceptores propios de BrowserGuard", () => {
    const { Monitor, Events, Context } = Setup();
    window.fetch = (() => Promise.resolve(null)) as unknown as typeof window.fetch;
    Monitor.Start();
    Context.Flush();
    Events.length = 0;

    const patch = new FunctionPatch(window, "fetch", {}, Context);
    patch.Apply();
    restorers.push(() => {
      patch.Restore();
    });
    Monitor.CheckNow();
    Context.Flush();
    expect(Events).toHaveLength(0);
    Monitor.Stop();
  });

  it("CheckNow no hace nada si el monitor está detenido", () => {
    const { Monitor, Events, Context } = Setup();
    Monitor.CheckNow();
    Context.Flush();
    expect(Events).toHaveLength(0);
  });
});

describe("RuntimeIntegrityDetector", () => {
  function Evaluate(data: RuntimeModificationData): SecurityFinding | null {
    const event: SecurityEvent<RuntimeModificationData> = {
      Id: "evt-1",
      Timestamp: 1,
      Type: "runtime.modified",
      Source: "Test",
      Data: data,
    };
    return new RiskEngine({}, "info").Evaluate(
      new RuntimeIntegrityDetector().Analyze(event),
      event,
    );
  }

  const NonNative = { LooksNative: false, Confidence: 0.8, Signals: ["non-native-source"] };
  const Native = { LooksNative: true, Confidence: 1, Signals: [] };

  it("reemplazo por función no nativa → high", () => {
    const finding = Evaluate({ Target: "window.fetch", Phase: "change", Analysis: NonNative });
    expect(finding?.Severity).toBe("high");
    expect(finding?.Title).toBe("window.fetch modified");
    expect(finding?.Description).toContain("does not look native");
  });

  it("reemplazo por algo que parece nativo (Proxy/bind) → medium", () => {
    const finding = Evaluate({ Target: "window.fetch", Phase: "change", Analysis: Native });
    expect(finding?.Severity).toBe("medium");
    expect(finding?.Description).toContain("still looks native");
  });

  it("reemplazo de eval por función no nativa → critical", () => {
    const finding = Evaluate({ Target: "eval", Phase: "change", Analysis: NonNative });
    expect(finding?.Severity).toBe("critical");
  });

  it("modificación previa al inicio → medium", () => {
    const finding = Evaluate({ Target: "setTimeout", Phase: "baseline", Analysis: NonNative });
    expect(finding?.Severity).toBe("medium");
    expect(finding?.Description).toContain("already modified");
  });

  it("función eliminada → medium", () => {
    const finding = Evaluate({ Target: "setInterval", Phase: "removed" });
    expect(finding?.Severity).toBe("medium");
    expect(finding?.Title).toBe("setInterval removed");
  });
});
