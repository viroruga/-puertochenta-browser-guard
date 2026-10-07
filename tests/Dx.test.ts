import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { ResolveConfig } from "../src/Config/ResolveConfig";
import { ExpandServices, KnownServices, ResolveServices } from "../src/Config/Services";
import { GuardContext } from "../src/Core/GuardContext";
import { GuardStore } from "../src/Core/GuardStore";
import { MaxLearnedOrigins, OriginLearner } from "../src/Core/OriginLearner";
import { RuntimeMonitor } from "../src/Monitors/RuntimeMonitor";
import type { BrowserGuardConfig } from "../src/Types/BrowserGuardConfig";
import type { GuardSnapshot } from "../src/Types/GuardStatus";
import type {
  DomElementData,
  NetworkRequestData,
  RuntimeModificationData,
  SecurityEvent,
} from "../src/Types/SecurityEvent";
import { FlushTasks, ResetGuard } from "./Helpers";

const EmptyStatistics = { Total: 0, Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };

function Snapshot(patch: Partial<GuardSnapshot> = {}): GuardSnapshot {
  return { Running: false, Bot: null, LastFinding: null, Statistics: EmptyStatistics, ...patch };
}

describe("GuardStore", () => {
  it("mantiene la identidad del snapshot hasta que cambia", () => {
    const store = new GuardStore(Snapshot(), vi.fn());
    const first = store.Get();
    expect(store.Get()).toBe(first);
    expect(Object.isFrozen(first)).toBe(true);
    store.Update({ Running: true });
    expect(store.Get()).not.toBe(first);
    expect(store.Get().Running).toBe(true);
  });

  it("notifica a los suscriptores y permite desuscribirse", () => {
    const store = new GuardStore(Snapshot(), vi.fn());
    const listener = vi.fn();
    const unsubscribe = store.Subscribe(listener);
    store.Update({ Running: true });
    unsubscribe();
    store.Update({ Running: false });
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("aísla los errores de un listener", () => {
    const onError = vi.fn();
    const store = new GuardStore(Snapshot(), onError);
    const after = vi.fn();
    store.Subscribe(() => {
      throw new Error("boom");
    });
    store.Subscribe(after);
    store.Update({ Running: true });
    expect(onError).toHaveBeenCalledTimes(1);
    expect(after).toHaveBeenCalledTimes(1);
  });

  it("Subscribe y GetSnapshot son funciones enlazadas (useSyncExternalStore)", () => {
    const store = new GuardStore(Snapshot(), vi.fn());
    const { Get, Subscribe } = store;
    const listener = vi.fn();
    Subscribe(listener);
    store.Update({ Running: true });
    expect(Get().Running).toBe(true);
    expect(listener).toHaveBeenCalled();
  });
});

describe("BrowserGuard store", () => {
  afterEach(() => {
    ResetGuard();
    document.body.innerHTML = "";
  });

  it("refleja inicio, hallazgos y detención", async () => {
    const guard = BrowserGuard.Start({ Console: false, Preset: "development" });
    const { GetSnapshot, Subscribe } = guard;
    const listener = vi.fn();
    Subscribe(listener);
    expect(GetSnapshot()).toMatchObject({ Running: true, Bot: null, LastFinding: null });

    const script = document.createElement("script");
    script.src = "https://unknown.example/x.js";
    document.body.appendChild(script);
    await FlushTasks();

    const snapshot = GetSnapshot();
    expect(snapshot.LastFinding?.Category).toBe("script-injection");
    expect(snapshot.Statistics.Total).toBeGreaterThan(0);
    expect(listener).toHaveBeenCalled();

    guard.Stop();
    expect(GetSnapshot().Running).toBe(false);
    // El snapshot sigue disponible después de Stop().
    expect(GetSnapshot().LastFinding).toBe(snapshot.LastFinding);
  });
});

describe("Services", () => {
  afterEach(() => {
    ResetGuard();
    document.body.innerHTML = "";
  });

  it("filtra nombres desconocidos y repetidos", () => {
    expect(ResolveServices(["stripe", "nope", "stripe", 42])).toEqual(["stripe"]);
    expect(ResolveServices("stripe")).toEqual([]);
    expect(KnownServices).toContain("zone.js");
  });

  it("agrega los orígenes de los servicios a las listas permitidas", () => {
    const config = ResolveConfig({
      Services: ["stripe", "sentry"],
      Network: { AllowedOrigins: ["https://api.example.com"] },
    });
    expect(config.Services).toEqual(["stripe", "sentry"]);
    expect(config.Network.AllowedOrigins).toEqual(
      expect.arrayContaining(["https://api.example.com", "https://*.stripe.com"]),
    );
    expect(config.Dom.AllowedScriptOrigins).toContain("https://js.stripe.com");
    expect(config.Integrity.TrustedWrapperMarkers).toEqual(["__sentry_original__"]);
  });

  it("sin servicios no agrega nada", () => {
    const config = ResolveConfig();
    expect(config.Services).toEqual([]);
    expect(config.Integrity.TrustedWrapperMarkers).toEqual([]);
    expect(ExpandServices([])).toEqual({ Scripts: [], Network: [], WrapperMarkers: [] });
  });

  it("no duplica orígenes compartidos entre servicios", () => {
    const expanded = ExpandServices(["google-analytics", "google-tag-manager"]);
    expect(expanded.Scripts.filter((o) => o === "https://www.googletagmanager.com")).toHaveLength(
      1,
    );
  });

  it("un script de un servicio declarado no genera hallazgo", async () => {
    const guard = BrowserGuard.Start({
      Console: false,
      Preset: "development",
      Services: ["stripe"],
    });
    const script = document.createElement("script");
    script.src = "https://js.stripe.com/v3/";
    document.body.appendChild(script);
    await FlushTasks();
    expect(
      guard.GetReport().Findings.filter((finding) => finding.Category === "script-injection"),
    ).toEqual([expect.objectContaining({ Title: "Known external script inserted" })]);
  });
});

describe("Wrappers confiables", () => {
  const restorers: (() => void)[] = [];

  afterEach(() => {
    for (const restore of restorers.splice(0)) {
      restore();
    }
  });

  function Setup(config: BrowserGuardConfig): {
    Monitor: RuntimeMonitor;
    Events: SecurityEvent<RuntimeModificationData>[];
    Context: GuardContext;
  } {
    const events: SecurityEvent<RuntimeModificationData>[] = [];
    const context = new GuardContext(ResolveConfig(config), window, (event) => {
      events.push(event as SecurityEvent<RuntimeModificationData>);
    });
    return { Monitor: new RuntimeMonitor(context), Events: events, Context: context };
  }

  function WrapSetTimeout(marker: string, target?: unknown): void {
    const original = window.setTimeout;
    const wrapper = function setTimeout(...args: Parameters<typeof original>) {
      return original(...args);
    } as typeof window.setTimeout;
    Object.defineProperty(wrapper, marker, { value: target ?? original });
    window.setTimeout = wrapper;
    restorers.push(() => (window.setTimeout = original));
  }

  function Changes(events: SecurityEvent<RuntimeModificationData>[]): string[] {
    return events.filter((e) => e.Data.Phase === "change").map((e) => e.Data.Target);
  }

  it("ignora el wrapper de Sentry si el servicio está declarado", () => {
    const { Monitor, Events, Context } = Setup({ Services: ["sentry"] });
    Monitor.Start();
    WrapSetTimeout("__sentry_original__");
    Monitor.CheckNow();
    Context.Flush();
    expect(Changes(Events)).not.toContain("setTimeout");
    Monitor.Stop();
  });

  it("sigue cadenas de wrappers (Zone.js sobre Sentry)", () => {
    const { Monitor, Events, Context } = Setup({ Services: ["sentry", "zone.js"] });
    Monitor.Start();
    WrapSetTimeout("__sentry_original__");
    WrapSetTimeout("__zone_symbol__OriginalDelegate");
    Monitor.CheckNow();
    Context.Flush();
    expect(Changes(Events)).not.toContain("setTimeout");
    Monitor.Stop();
  });

  it("reporta la marca si el servicio no está declarado", () => {
    const { Monitor, Events, Context } = Setup({});
    Monitor.Start();
    WrapSetTimeout("__sentry_original__");
    Monitor.CheckNow();
    Context.Flush();
    expect(Changes(Events)).toContain("setTimeout");
    Monitor.Stop();
  });

  it("reporta una marca falsificada que no apunta a la referencia legítima", () => {
    const { Monitor, Events, Context } = Setup({ Services: ["sentry"] });
    Monitor.Start();
    WrapSetTimeout("__sentry_original__", () => undefined);
    Monitor.CheckNow();
    Context.Flush();
    expect(Changes(Events)).toContain("setTimeout");
    Monitor.Stop();
  });

  it("tolera marcas con getters que lanzan", () => {
    const { Monitor, Events, Context } = Setup({ Services: ["sentry"] });
    Monitor.Start();
    const original = window.setTimeout;
    const wrapper = function setTimeout() {
      return 0;
    } as unknown as typeof window.setTimeout;
    Object.defineProperty(wrapper, "__sentry_original__", {
      get() {
        throw new Error("trap");
      },
    });
    window.setTimeout = wrapper;
    restorers.push(() => (window.setTimeout = original));
    expect(() => {
      Monitor.CheckNow();
    }).not.toThrow();
    Context.Flush();
    expect(Changes(Events)).toContain("setTimeout");
    Monitor.Stop();
  });

  it("acepta en el baseline un wrapper previo sobre una función nativa", () => {
    const original = window.eval;
    const wrapper = function eval_(code: string): unknown {
      return original(code);
    };
    Object.defineProperty(wrapper, "__sentry_original__", { value: original });
    window.eval = wrapper;
    restorers.push(() => (window.eval = original));

    const declared = Setup({ Services: ["sentry"] });
    declared.Monitor.Start();
    declared.Context.Flush();
    expect(declared.Events.map((e) => e.Data.Target)).not.toContain("eval");
    declared.Monitor.Stop();

    const undeclared = Setup({});
    undeclared.Monitor.Start();
    undeclared.Context.Flush();
    expect(undeclared.Events.map((e) => e.Data.Target)).toContain("eval");
    undeclared.Monitor.Stop();
  });
});

describe("OriginLearner", () => {
  afterEach(() => {
    ResetGuard();
    document.body.innerHTML = "";
  });

  const PageOrigin = "https://app.example.com";

  function Learner(config: BrowserGuardConfig = {}): OriginLearner {
    return new OriginLearner(ResolveConfig(config), () => PageOrigin);
  }

  function Request(origin: string | null): NetworkRequestData {
    return {
      Transport: "fetch",
      Url: `${origin ?? ""}/x`,
      Origin: origin,
      HasQuery: false,
      QueryLength: 0,
    };
  }

  function Element(tag: DomElementData["TagName"], origin: string | null): DomElementData {
    return {
      TagName: tag,
      Src: null,
      Origin: origin,
      Scheme: "https",
      Inline: false,
      ParserInserted: false,
    };
  }

  it("propone orígenes de red y de scripts no permitidos", () => {
    const learner = Learner({
      Network: {
        AllowedOrigins: ["https://*.cdn.example"],
        BlockedOrigins: ["https://evil.example"],
      },
    });
    learner.ObserveRequest(Request("https://API.partner.example"));
    learner.ObserveRequest(Request("https://api.partner.example"));
    learner.ObserveRequest(Request(PageOrigin));
    learner.ObserveRequest(Request("https://img.cdn.example"));
    learner.ObserveRequest(Request("https://evil.example"));
    learner.ObserveRequest(Request(null));
    learner.ObserveRequest(Request("chrome-extension://abc"));
    learner.ObserveElement(Element("script", "https://widget.example"));
    learner.ObserveElement(Element("iframe", "https://video.example"));
    expect(learner.GetLearnedConfig()).toEqual({
      Network: { AllowedOrigins: ["https://api.partner.example", "https://video.example"] },
      Dom: { AllowedScriptOrigins: ["https://widget.example"] },
    });
  });

  it("acota la cantidad de orígenes", () => {
    const learner = Learner();
    for (let i = 0; i < MaxLearnedOrigins + 10; i++) {
      learner.ObserveRequest(Request(`https://h${i}.example`));
    }
    expect(learner.GetLearnedConfig().Network?.AllowedOrigins).toHaveLength(MaxLearnedOrigins);
  });

  it("integrado: aprende scripts insertados y se consulta después de Stop()", async () => {
    expect(BrowserGuard.GetLearnedConfig()).toBeNull();
    const guard = BrowserGuard.Start({ Console: false, Learning: { Enabled: true } });
    const script = document.createElement("script");
    script.src = "https://widget.example/w.js";
    document.body.appendChild(script);
    await FlushTasks();
    expect(BrowserGuard.GetLearnedConfig()?.Dom?.AllowedScriptOrigins).toEqual([
      "https://widget.example",
    ]);
    guard.Stop();
    expect(guard.GetLearnedConfig()?.Dom?.AllowedScriptOrigins).toEqual(["https://widget.example"]);
    document.body.innerHTML = "";
  });

  it("deshabilitado por defecto", () => {
    const guard = BrowserGuard.Start({ Console: false });
    expect(guard.GetLearnedConfig()).toBeNull();
    guard.Stop();
  });
});
