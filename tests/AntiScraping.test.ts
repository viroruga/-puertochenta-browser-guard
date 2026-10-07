import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { AntiScraping } from "../src/Plugins/AntiScrapingPlugin";
import {
  AntiScrapingDefaults,
  ResolveAntiScrapingConfig,
} from "../src/Config/ResolveAntiScrapingConfig";
import { BotSession } from "../src/Core/BotSession";
import { RiskEngine } from "../src/Core/RiskEngine";
import { BotDetector, NoInteractionAfterMs } from "../src/Detectors/BotDetector";
import { RequestPatternTracker } from "../src/Detectors/RequestPatternTracker";
import { SyntheticEventThreshold } from "../src/Monitors/InteractionMonitor";
import { ContentShield, ShieldedAttribute } from "../src/Protection/ContentShield";
import type { BotAssessment } from "../src/Types/Bot";
import type { ResolvedAntiScrapingConfig } from "../src/Types/BrowserGuardConfig";
import type { BotActivityData, SecurityEvent, SecurityEventType } from "../src/Types/SecurityEvent";
import { DetectAutomationSignals, DetectEnvironmentSignals } from "../src/Utils/AutomationSignals";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

type FakeWindow = Window & typeof globalThis;

function Settings(overrides: Partial<ResolvedAntiScrapingConfig> = {}): ResolvedAntiScrapingConfig {
  const resolved = ResolveAntiScrapingConfig({ Enabled: true });
  if (!resolved) {
    throw new Error("invalid");
  }
  return { ...resolved, ...overrides };
}

function Event(type: SecurityEventType, data: unknown, timestamp = 0): SecurityEvent {
  return { Id: "evt", Timestamp: timestamp, Type: type, Source: "Test", Data: data };
}

function Activity(overrides: Partial<BotActivityData> = {}): BotActivityData {
  return {
    Reason: "checkpoint",
    ElapsedMs: 10_000,
    Pointer: 0,
    Keyboard: 0,
    Scroll: 0,
    Touch: 0,
    Untrusted: 0,
    Visible: true,
    ...overrides,
  };
}

describe("ResolveAntiScrapingConfig", () => {
  it("activo por defecto al usar el plugin; Enabled: false lo desactiva", () => {
    expect(ResolveAntiScrapingConfig()).not.toBeNull();
    expect(ResolveAntiScrapingConfig("invalid")).not.toBeNull();
    expect(ResolveAntiScrapingConfig({ Enabled: false })).toBeNull();
  });

  it("aplica valores por defecto seguros", () => {
    expect(ResolveAntiScrapingConfig({})).toEqual({
      Signals: { Automation: true, RequestRate: true, Interaction: true, Environment: true },
      MaxRequestsPerMinute: 120,
      SequentialThreshold: 10,
      ProtectSelector: "[data-guard-protect]",
      ProtectAt: "bot",
      Placeholder: AntiScrapingDefaults.Placeholder,
      VerdictHeader: { Enabled: true, Name: "X-BrowserGuard-Verdict", Origins: [] },
    });
  });

  it("valida selector, nombre de header, límites y orígenes", () => {
    const config = ResolveAntiScrapingConfig({
      Enabled: true,
      Signals: { Environment: false },
      ProtectSelector: "[[invalid",
      ProtectAt: "suspicious",
      Placeholder: "x".repeat(900),
      MaxRequestsPerMinute: 1,
      SequentialThreshold: 99_999,
      VerdictHeader: { Name: "Bad Header", Origins: ["https://API.example.com/x", "nope"] },
    });
    expect(config).toMatchObject({
      Signals: { Environment: false, Automation: true },
      ProtectSelector: "[data-guard-protect]",
      ProtectAt: "suspicious",
      MaxRequestsPerMinute: 10,
      SequentialThreshold: 1000,
      VerdictHeader: { Name: "X-BrowserGuard-Verdict", Origins: ["https://api.example.com"] },
    });
    expect(config?.Placeholder).toHaveLength(500);
  });
});

describe("AutomationSignals", () => {
  function FakeAutomationWindow(
    navigator: object,
    extra: object = {},
    documentKeys: object = {},
  ): FakeWindow {
    const document = Object.assign(
      window.document.implementation.createHTMLDocument("x"),
      documentKeys,
    );
    return { navigator, document, ...extra } as unknown as FakeWindow;
  }

  it("un navegador limpio no produce señales", () => {
    expect(
      DetectAutomationSignals(FakeAutomationWindow({ userAgent: "Mozilla/5.0 Chrome/130" })),
    ).toEqual([]);
  });

  it("detecta webdriver, headless y user agent data", () => {
    expect(
      DetectAutomationSignals(
        FakeAutomationWindow({ webdriver: true, userAgent: "HeadlessChrome/130" }),
      ),
    ).toEqual(["webdriver", "headless"]);
    expect(
      DetectAutomationSignals(
        FakeAutomationWindow({
          userAgent: "Chrome",
          userAgentData: { brands: [{ brand: "HeadlessChrome" }] },
        }),
      ),
    ).toEqual(["headless"]);
  });

  it("detecta rastros de frameworks de automatización", () => {
    const fake = FakeAutomationWindow(
      { userAgent: "Chrome" },
      { __playwright__binding__: {}, callPhantom: () => undefined },
      { $cdc_asdjflasutopfhvcZLmcfl_: {} },
    );
    fake.document.documentElement.setAttribute("webdriver", "");
    expect(DetectAutomationSignals(fake).sort()).toEqual(
      [
        "artifact:chromedriver",
        "artifact:phantomjs",
        "artifact:playwright",
        "artifact:webdriver-attribute",
      ].sort(),
    );
  });

  it("detecta inconsistencias del entorno sin exponer valores", () => {
    const canvas = {
      getContext: () => ({
        getExtension: (name: string) =>
          name === "WEBGL_debug_renderer_info"
            ? { UNMASKED_RENDERER_WEBGL: 1 }
            : { loseContext: vi.fn() },
        getParameter: () => "Google SwiftShader",
      }),
    };
    const fake = {
      navigator: {
        userAgent: "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0",
        platform: "Linux x86_64",
        languages: [],
        plugins: { length: 0 },
      },
      outerWidth: 0,
      outerHeight: 0,
      document: { createElement: () => canvas },
    } as unknown as FakeWindow;
    expect(DetectEnvironmentSignals(fake)).toEqual([
      "env-no-languages",
      "env-zero-window",
      "env-ua-mismatch",
      "env-no-plugins",
      "env-software-gl",
    ]);
  });

  it("Chrome sin window.chrome se considera inconsistente; un entorno normal no", () => {
    const base = {
      outerWidth: 1200,
      outerHeight: 800,
      document: { createElement: () => ({ getContext: () => null }) },
    };
    const chromeWithoutObjectFields = {
      ...base,
      navigator: {
        userAgent: "Mozilla/5.0 (X11; Linux) Chrome/130",
        platform: "Linux",
        languages: ["es"],
        plugins: { length: 5 },
      },
    };
    const chromeWithoutObject = chromeWithoutObjectFields as unknown as FakeWindow;
    expect(DetectEnvironmentSignals(chromeWithoutObject)).toEqual(["env-ua-mismatch"]);
    const normal = { ...chromeWithoutObjectFields, chrome: {} } as unknown as FakeWindow;
    expect(DetectEnvironmentSignals(normal)).toEqual([]);
  });

  it("tolera errores al consultar WebGL", () => {
    const fake = {
      navigator: { userAgent: "Firefox", platform: "Win32", languages: ["es"] },
      outerWidth: 1,
      outerHeight: 1,
      document: {
        createElement: () => {
          throw new Error("blocked");
        },
      },
    } as unknown as FakeWindow;
    expect(DetectEnvironmentSignals(fake)).toEqual([]);
  });
});

describe("RequestPatternTracker", () => {
  it("detecta ráfagas dentro de la ventana de un minuto", () => {
    const tracker = new RequestPatternTracker(5);
    for (let i = 0; i < 5; i++) {
      expect(tracker.Record("https://a.example/x", i).Burst).toBe(false);
    }
    expect(tracker.Record("https://a.example/x", 5).Burst).toBe(true);
    expect(tracker.Record("https://a.example/x", 120_000).RequestsLastMinute).toBe(1);
  });

  it("detecta barridos secuenciales en ambas direcciones", () => {
    const tracker = new RequestPatternTracker(1000);
    let run = 0;
    for (let id = 1; id <= 5; id++) {
      run = tracker.Record(`https://a.example/product/${id}/detail`, id).SequentialRun;
    }
    expect(run).toBe(5);
    expect(tracker.Record("https://a.example/product/4/detail", 6)).toMatchObject({
      SequentialRun: 6,
      Template: "https://a.example/product/{n}/detail",
    });
    expect(tracker.Record("https://a.example/product/40/detail", 7).SequentialRun).toBe(1);
    expect(tracker.Record("https://a.example/about", 8)).toMatchObject({
      Template: null,
      SequentialRun: 0,
    });
  });

  it("limita la cantidad de plantillas recordadas", () => {
    const tracker = new RequestPatternTracker(10_000);
    for (let i = 0; i < 150; i++) {
      tracker.Record(`https://a.example/t${i}/1`, i);
    }
    expect(tracker.Record("https://a.example/t0/2", 200).SequentialRun).toBe(1);
    expect(tracker.Record("https://a.example/t149/2", 201).SequentialRun).toBe(2);
  });
});

describe("BotDetector", () => {
  it("traduce señales de entorno y las reporta una sola vez", () => {
    const detector = new BotDetector(Settings());
    const first = detector.Analyze(
      Event("bot.environment", {
        Phase: "start",
        Signals: ["webdriver", "artifact:playwright", "unknown"],
      }),
    );
    expect(first).toMatchObject({
      Category: "bot",
      Title: "Browser automation detected",
      Signals: ["bot.webdriver", "bot.automation-artifact"],
    });
    expect(
      detector.Analyze(
        Event("bot.environment", { Phase: "recheck", Signals: ["artifact:selenium"] }),
      ),
    ).toBeNull();
  });

  it("señales solo de entorno se titulan como inconsistencia", () => {
    const detector = new BotDetector(Settings());
    const candidate = detector.Analyze(
      Event("bot.environment", {
        Phase: "start",
        Signals: [
          "headless",
          "env-software-gl",
          "env-no-languages",
          "env-zero-window",
          "env-ua-mismatch",
          "env-no-plugins",
        ],
      }),
    );
    expect(candidate?.Signals).toHaveLength(6);
    const envOnly = new BotDetector(Settings()).Analyze(
      Event("bot.environment", { Phase: "start", Signals: ["env-software-gl"] }),
    );
    expect(envOnly?.Title).toBe("Inconsistent browser environment");
  });

  it("interacción humana, eventos sintéticos y ausencia de interacción", () => {
    const detector = new BotDetector(Settings());
    expect(
      detector.Analyze(
        Event("bot.activity", Activity({ Reason: "first-interaction", Pointer: 1 })),
      ),
    ).toMatchObject({ Title: "Human interaction observed", Signals: ["bot.human-interaction"] });

    const synthetic = new BotDetector(Settings()).Analyze(
      Event(
        "bot.activity",
        Activity({ Reason: "synthetic-threshold", Untrusted: SyntheticEventThreshold }),
      ),
    );
    expect(synthetic).toMatchObject({
      Title: "Non-human interaction pattern",
      Signals: ["bot.synthetic-events"],
    });
    expect(synthetic?.Description).toContain("generated by scripts");

    const idle = new BotDetector(Settings());
    expect(idle.Analyze(Event("bot.activity", Activity({ ElapsedMs: 10_000 })))).toBeNull();
    expect(
      idle.Analyze(
        Event("bot.activity", Activity({ ElapsedMs: NoInteractionAfterMs, Visible: false })),
      ),
    ).toBeNull();
    expect(
      idle.Analyze(Event("bot.activity", Activity({ ElapsedMs: NoInteractionAfterMs, Scroll: 2 }))),
    ).toBeNull();
    expect(
      idle.Analyze(Event("bot.activity", Activity({ ElapsedMs: NoInteractionAfterMs })))?.Signals,
    ).toEqual(["bot.no-interaction"]);
  });

  it("respeta las señales deshabilitadas", () => {
    const detector = new BotDetector(
      Settings({
        Signals: { Automation: true, Environment: true, Interaction: false, RequestRate: false },
      }),
    );
    expect(detector.Analyze(Event("bot.activity", Activity({ Untrusted: 50 })))).toBeNull();
    expect(
      detector.Analyze(
        Event("network.request", {
          Transport: "fetch",
          Url: "https://a.example/p/1",
          Origin: "https://a.example",
          HasQuery: false,
        }),
      ),
    ).toBeNull();
  });

  it("detecta barridos secuenciales y ráfagas de solicitudes", () => {
    const detector = new BotDetector(
      Settings({ SequentialThreshold: 3, MaxRequestsPerMinute: 10 }),
    );
    const request = (id: number, t: number): SecurityEvent =>
      Event(
        "network.request",
        {
          Transport: "fetch",
          Url: `https://a.example/item/${id}`,
          Origin: "https://a.example",
          HasQuery: false,
        },
        t,
      );
    expect(detector.Analyze(request(1, 0))).toBeNull();
    expect(detector.Analyze(request(2, 1))).toBeNull();
    const crawl = detector.Analyze(request(3, 2));
    expect(crawl).toMatchObject({
      Title: "Scraping-like request pattern",
      Signals: ["bot.sequential-crawl"],
    });
    expect(crawl?.Description).toContain("https://a.example/item/{n}");

    let burst = null;
    for (let i = 0; i < 12 && !burst; i++) {
      burst = detector.Analyze(request(100 + i * 10, 3 + i));
    }
    expect(burst?.Signals).toEqual(["bot.request-burst"]);
    expect(burst?.Description).toContain("requests in the last minute");
  });

  it("ignora solicitudes sin origen de red y eventos ajenos", () => {
    const detector = new BotDetector(Settings());
    expect(
      detector.Analyze(
        Event("network.request", {
          Transport: "fetch",
          Url: "data:[redacted]",
          Origin: null,
          HasQuery: false,
        }),
      ),
    ).toBeNull();
    expect(detector.Analyze(Event("csp.violation", {}))).toBeNull();
  });
});

describe("BotSession", () => {
  function Create(): { Session: BotSession; Changes: BotAssessment[] } {
    const changes: BotAssessment[] = [];
    return { Session: new BotSession(new RiskEngine(), (a) => changes.push(a)), Changes: changes };
  }

  it("transita unknown → human → suspicious → bot y notifica solo cambios", () => {
    const { Session, Changes } = Create();
    expect(Session.Get().Verdict).toBe("unknown");
    Session.Add(["bot.human-interaction"]);
    Session.Add(["bot.human-interaction", "network.unknown-origin"]);
    Session.Add(["bot.sequential-crawl"]);
    Session.Add(["bot.synthetic-events"]);
    expect(Changes.map((change) => change.Verdict)).toEqual(["human", "suspicious", "bot"]);
    expect(Session.Get()).toMatchObject({ Verdict: "bot", Score: 75 });
  });

  it("la interacción compensa señales pasivas pero no el comportamiento automatizado", () => {
    const passive = Create().Session;
    passive.Add(["bot.env-software-gl", "bot.env-ua-mismatch"]);
    passive.Add(["bot.human-interaction"]);
    expect(passive.Get()).toMatchObject({ Verdict: "human", Score: 25 });

    const behavioral = Create().Session;
    behavioral.Add(["bot.human-interaction", "bot.sequential-crawl"]);
    expect(behavioral.Get()).toMatchObject({ Verdict: "suspicious", Score: 45 });
  });

  it("la interacción no rebaja señales concluyentes de automatización", () => {
    const { Session } = Create();
    Session.Add(["bot.webdriver"]);
    Session.Add(["bot.human-interaction"]);
    expect(Session.Get()).toMatchObject({ Verdict: "bot", Score: 80 });
  });

  it("el veredicto bot es persistente", () => {
    const { Session } = Create();
    Session.Add(["bot.env-software-gl", "bot.env-ua-mismatch", "bot.env-zero-window"]);
    Session.Add(["bot.human-interaction"]);
    expect(Session.Get().Verdict).toBe("bot");
    expect(Session.Get().Score).toBe(45);
  });

  it("Get retorna copias", () => {
    const { Session } = Create();
    Session.Add(["bot.webdriver"]);
    Session.Get().Signals.push("x");
    expect(Session.Get().Signals).toEqual(["bot.webdriver"]);
  });
});

describe("ContentShield", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("retira el contenido protegido del DOM y lo repone intacto", async () => {
    document.body.innerHTML =
      '<div id="price" data-guard-protect><span class="amount">$99</span> oferta</div><p id="free">libre</p>';
    const original = document.querySelector("#price")?.innerHTML;
    const shield = new ContentShield(window, "[data-guard-protect]", "No disponible");
    shield.Activate();
    shield.Activate();

    const price = document.querySelector("#price");
    expect(price?.textContent).toBe("No disponible");
    expect(price?.hasAttribute(ShieldedAttribute)).toBe(true);
    expect(document.body.textContent).not.toContain("$99");
    expect(document.querySelector("#free")?.textContent).toBe("libre");
    expect(shield.ShieldedCount).toBe(1);

    // Contenido protegido insertado después, y contenido re-agregado a un elemento protegido.
    const late = document.createElement("section");
    late.innerHTML = "<div data-guard-protect>secreto</div>";
    document.body.appendChild(late);
    price?.appendChild(document.createTextNode("re-render"));
    await Promise.resolve();
    expect(document.body.textContent).not.toContain("secreto");
    expect(price?.textContent).toBe("No disponible");

    shield.Restore();
    expect(shield.IsActive()).toBe(false);
    expect(price?.innerHTML).toBe(`${original ?? ""}re-render`);
    expect(price?.hasAttribute(ShieldedAttribute)).toBe(false);
    expect(late.textContent).toBe("secreto");
  });
});

describe("Anti-scraping integrado", () => {
  const navigatorDescriptor = Object.getOwnPropertyDescriptor(navigator, "webdriver");

  beforeEach(() => {
    document.body.innerHTML = '<div id="catalog" data-guard-protect>Precio: $99</div>';
  });

  afterEach(() => {
    ResetGuard();
    vi.useRealTimers();
    document.body.innerHTML = "";
    if (navigatorDescriptor) {
      Object.defineProperty(navigator, "webdriver", navigatorDescriptor);
    } else {
      Reflect.deleteProperty(navigator, "webdriver");
    }
  });

  const BaseConfig = {
    Console: "silent",
    Monitors: {
      Xhr: false,
      WebSocket: false,
      Dom: false,
      Csp: false,
      Prototype: false,
      Runtime: false,
      Sinks: false,
    },
  } as const;

  it("deshabilitado por defecto: sin monitores ni veredicto", () => {
    const guard = BrowserGuard.Start(BaseConfig);
    expect(guard.GetBotAssessment()).toBeNull();
    expect(guard.GetStatus().Bot).toBeNull();
    expect(guard.GetStatus().Monitors.map((monitor) => monitor.Name)).toEqual(["FetchMonitor"]);
  });

  it("webdriver → veredicto bot, evento Bot y contenido protegido", async () => {
    Object.defineProperty(navigator, "webdriver", { configurable: true, get: () => true });
    const onBot = vi.fn();
    const handler = vi.fn();
    BrowserGuard.On("Bot", handler);
    const guard = BrowserGuard.Start({
      ...BaseConfig,
      Plugins: [AntiScraping({ Placeholder: "—", Signals: { Environment: false } })],
    });
    guard.On("Bot", onBot);
    await FlushMicrotasks();

    expect(onBot).toHaveBeenCalledWith(expect.objectContaining({ Verdict: "bot" }));
    expect(guard.GetBotAssessment()?.Verdict).toBe("bot");
    expect(BrowserGuard.GetBotAssessment()?.Signals).toContain("bot.webdriver");
    expect(document.querySelector("#catalog")?.textContent).toBe("—");
    expect(guard.GetReport().Findings.some((finding) => finding.Category === "bot")).toBe(true);

    guard.Stop();
    expect(document.querySelector("#catalog")?.textContent).toBe("Precio: $99");
  });

  it("agrega el header de veredicto solo al propio origen y a los configurados", async () => {
    const original = vi.fn((_input: unknown, _init?: RequestInit) => Promise.resolve(null));
    window.fetch = original as unknown as typeof window.fetch;
    const guard = BrowserGuard.Start({
      ...BaseConfig,
      Plugins: [
        AntiScraping({
          Signals: { Environment: false, Interaction: false },
          VerdictHeader: { Origins: ["https://api.example.com"] },
        }),
      ],
    });
    await window.fetch("/api/catalog", { method: "POST", headers: { "X-App": "1" } });
    await window.fetch("https://api.example.com/v1");
    await window.fetch("https://other.example/v1");

    const sid = guard.GetStatus().SessionId;
    const sameOrigin = new Headers(original.mock.calls[0]?.[1]?.headers);
    expect(sameOrigin.get("X-BrowserGuard-Verdict")).toBe(`unknown; score=0; sid=${sid ?? ""}`);
    expect(sameOrigin.get("X-App")).toBe("1");
    expect(original.mock.calls[0]?.[1]?.method).toBe("POST");
    expect(new Headers(original.mock.calls[1]?.[1]?.headers).has("X-BrowserGuard-Verdict")).toBe(
      true,
    );
    expect(original.mock.calls[2]?.[1]).toBeUndefined();

    guard.Stop();
    await window.fetch("/api/catalog");
    expect(original.mock.calls[3]?.[1]).toBeUndefined();
  });

  it("respeta un header de veredicto ya definido por la aplicación y Request como entrada", async () => {
    const original = vi.fn((_input: unknown, _init?: RequestInit) => Promise.resolve(null));
    window.fetch = original as unknown as typeof window.fetch;
    BrowserGuard.Start({
      ...BaseConfig,
      Plugins: [AntiScraping({ Signals: { Environment: false } })],
    });
    await window.fetch("/x", { headers: { "X-BrowserGuard-Verdict": "custom" } });
    expect(original.mock.calls[0]?.[1]?.headers).toEqual({ "X-BrowserGuard-Verdict": "custom" });

    if (typeof window.Request === "function") {
      const request = new window.Request(`${window.location.origin}/y`, {
        headers: { "X-Req": "a" },
      });
      await window.fetch(request);
      const headers = new Headers(original.mock.calls[1]?.[1]?.headers);
      expect(headers.get("X-Req")).toBe("a");
      expect(headers.has("X-BrowserGuard-Verdict")).toBe(true);
    }
  });

  it("VerdictHeader deshabilitado no modifica solicitudes", async () => {
    const original = vi.fn((_input: unknown, _init?: RequestInit) => Promise.resolve(null));
    window.fetch = original as unknown as typeof window.fetch;
    BrowserGuard.Start({
      ...BaseConfig,
      Plugins: [
        AntiScraping({
          Signals: { Environment: false },
          VerdictHeader: { Enabled: false },
        }),
      ],
    });
    await window.fetch("/x");
    expect(original.mock.calls[0]?.[1]).toBeUndefined();
  });

  it("XHR recibe el header de veredicto", () => {
    const prototype = XMLHttpRequest.prototype;
    const originalSend = prototype.send;
    prototype.send = vi.fn();
    const setHeader = vi.spyOn(prototype, "setRequestHeader");
    try {
      BrowserGuard.Start({
        ...BaseConfig,
        Monitors: { ...BaseConfig.Monitors, Xhr: true },
        Plugins: [AntiScraping({ Signals: { Environment: false } })],
      });
      const xhr = new XMLHttpRequest();
      xhr.open("GET", "/api/items");
      xhr.send();
      expect(setHeader).toHaveBeenCalledWith(
        "X-BrowserGuard-Verdict",
        expect.stringMatching(/^unknown; score=0; sid=/),
      );
    } finally {
      ResetGuard();
      prototype.send = originalSend;
    }
  });

  it("barrido secuencial + eventos sintéticos → bot y contenido protegido", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const verdicts: string[] = [];
    const guard = BrowserGuard.Start({
      ...BaseConfig,
      Plugins: [AntiScraping({ Signals: { Environment: false }, SequentialThreshold: 5 })],
    });
    guard.On("Bot", (assessment) => verdicts.push(assessment.Verdict));

    for (let id = 1; id <= 5; id++) {
      await window.fetch(`/product/${id}`);
    }
    await FlushMicrotasks();
    expect(verdicts).toEqual(["suspicious"]);
    expect(document.querySelector("#catalog")?.textContent).toBe("Precio: $99");

    // dispatchEvent genera eventos con isTrusted === false.
    for (let i = 0; i < SyntheticEventThreshold; i++) {
      document.body.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    }
    await FlushMicrotasks();
    expect(verdicts).toEqual(["suspicious", "bot"]);
    expect(document.querySelector("#catalog")?.textContent).toBe(AntiScrapingDefaults.Placeholder);
  });

  it("ProtectAt: suspicious protege antes", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    BrowserGuard.Start({
      ...BaseConfig,
      Plugins: [
        AntiScraping({
          Signals: { Environment: false },
          SequentialThreshold: 3,
          ProtectAt: "suspicious",
        }),
      ],
    });
    for (let id = 1; id <= 3; id++) {
      await window.fetch(`/product/${id}`);
    }
    await FlushMicrotasks();
    expect(document.querySelector("#catalog")?.hasAttribute(ShieldedAttribute)).toBe(true);
  });

  it("checkpoints de interacción: sin actividad durante 30 s → señal no-interaction", async () => {
    vi.useFakeTimers();
    const guard = BrowserGuard.Start({
      ...BaseConfig,
      Preset: "development",
      Plugins: [AntiScraping({ Signals: { Environment: false, Automation: false } })],
    });
    await vi.advanceTimersByTimeAsync(30_000);
    await FlushMicrotasks();
    expect(guard.GetBotAssessment()?.Signals).toEqual(["bot.no-interaction"]);
    expect(guard.GetBotAssessment()?.Verdict).toBe("unknown");
    guard.Stop();
    expect(vi.getTimerCount()).toBe(0);
  });
});
