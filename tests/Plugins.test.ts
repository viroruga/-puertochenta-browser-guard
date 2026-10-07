import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { AntiScraping } from "../src/Plugins/AntiScrapingPlugin";
import { RemoteReporting } from "../src/Plugins/RemoteReportingPlugin";
import type { GuardPlugin, PluginHost } from "../src/Types/Plugin";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

const Quiet = {
  Console: "silent",
  Monitors: {
    Xhr: false,
    WebSocket: false,
    Dom: false,
    Csp: false,
    Prototype: false,
    Runtime: false,
    Sinks: false,
    Channels: false,
    Realms: false,
  },
} as const;

describe("Plugins", () => {
  afterEach(() => {
    ResetGuard();
  });

  it("sin plugins, el núcleo no registra nada opcional", () => {
    const status = BrowserGuard.Start(Quiet).GetStatus();
    expect(status.Plugins).toEqual([]);
    expect(status.Bot).toBeNull();
    expect(status.Remote).toBeNull();
  });

  it("reporta el estado de cada plugin, incluido un endpoint inválido", () => {
    const guard = BrowserGuard.Start({
      ...Quiet,
      Plugins: [
        AntiScraping({ Signals: { Environment: false } }),
        RemoteReporting({ Endpoint: "http://insecure.example/findings" }),
      ],
    });
    expect(guard.GetStatus().Plugins).toEqual([
      { Name: "AntiScraping", Active: true },
      { Name: "RemoteReporting", Active: false },
    ]);
    expect(guard.GetStatus().Remote).toBeNull();
  });

  it("AntiScraping({ Enabled: false }) queda inactivo y sin monitores", () => {
    const guard = BrowserGuard.Start({ ...Quiet, Plugins: [AntiScraping({ Enabled: false })] });
    expect(guard.GetStatus().Plugins).toEqual([{ Name: "AntiScraping", Active: false }]);
    expect(guard.GetStatus().Monitors.map((monitor) => monitor.Name)).toEqual(["FetchMonitor"]);
    expect(guard.GetBotAssessment()).toBeNull();
  });

  it("ignora entradas inválidas y nombres repetidos", () => {
    const setup = vi.fn(() => true);
    const plugin: GuardPlugin = { Name: "Custom", Setup: setup };
    const guard = BrowserGuard.Start({
      ...Quiet,
      Plugins: [plugin, { Name: "Custom", Setup: setup }, null, { Name: 1 }] as GuardPlugin[],
    });
    expect(setup).toHaveBeenCalledTimes(1);
    expect(guard.GetStatus().Plugins).toEqual([
      { Name: "Custom", Active: true },
      { Name: "Custom", Active: false },
    ]);
  });

  it("un plugin que falla no afecta a los demás ni a la aplicación", () => {
    const broken: GuardPlugin = {
      Name: "Broken",
      Setup: () => {
        throw new Error("setup failed");
      },
    };
    const guard = BrowserGuard.Start({ ...Quiet, Plugins: [broken, AntiScraping()] });
    expect(guard.IsRunning()).toBe(true);
    expect(guard.GetStatus().Plugins).toEqual([
      { Name: "Broken", Active: false },
      { Name: "AntiScraping", Active: true },
    ]);
    expect(guard.GetStatus().InternalErrors).toBeGreaterThan(0);
  });

  it("un plugin propio puede aportar monitores, detectores y reporters, y recibe candidatos", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const report = vi.fn();
    const candidates = vi.fn();
    const disposed = vi.fn();
    const custom: GuardPlugin = {
      Name: "Audit",
      Setup: (host: PluginHost) => {
        host.AddReporter({ Name: "AuditReporter", Report: report });
        host.OnCandidate(candidates);
        host.OnCandidate(() => {
          throw new Error("listener bug");
        });
        host.OnDispose(disposed);
        return true;
      },
    };
    const guard = BrowserGuard.Start({ ...Quiet, Plugins: [custom] });
    await window.fetch("https://unknown.example/x");
    await FlushMicrotasks();

    expect(report).toHaveBeenCalledTimes(1);
    expect(candidates).toHaveBeenCalledWith(expect.objectContaining({ Category: "network" }));
    guard.Stop();
    expect(disposed).toHaveBeenCalledTimes(1);
  });
});
