import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { ShowConsoleNotice } from "../src/Reporters/ConsoleNotice";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

const NoticeShownKey = Symbol.for("puertochenta.browser-guard.notice-shown");

function ResetNotice(): void {
  Reflect.deleteProperty(globalThis, NoticeShownKey);
}

describe("ShowConsoleNotice", () => {
  beforeEach(ResetNotice);

  it("imprime título y mensaje una sola vez por página", () => {
    const output = { info: vi.fn() };
    expect(ShowConsoleNotice({ Title: "Aviso", Message: "Texto" }, output)).toBe(true);
    expect(ShowConsoleNotice({ Title: "Aviso", Message: "Texto" }, output)).toBe(false);
    expect(output.info).toHaveBeenCalledTimes(2);
    expect(output.info.mock.calls[0]?.[0]).toBe("%cAviso");
    expect(output.info.mock.calls[1]?.[0]).toBe("%cTexto");
  });

  it("escapa % para que no se interprete como formato", () => {
    const output = { info: vi.fn() };
    ShowConsoleNotice({ Title: "100% %s", Message: "x" }, output);
    expect(output.info.mock.calls[0]?.[0]).toBe("%c100%% %%s");
  });
});

describe("Modo de consola integrado", () => {
  beforeEach(ResetNotice);

  afterEach(() => {
    ResetGuard();
  });

  const NetworkOnly = {
    Monitors: {
      Xhr: false,
      WebSocket: false,
      Dom: false,
      Csp: false,
      Prototype: false,
      Runtime: false,
    },
  } as const;

  function SpyConsole() {
    return {
      info: vi.spyOn(console, "info").mockImplementation(() => undefined),
      warn: vi.spyOn(console, "warn").mockImplementation(() => undefined),
      group: vi.spyOn(console, "groupCollapsed").mockImplementation(() => undefined),
    };
  }

  it("notice (por defecto en producción): muestra el aviso y oculta los hallazgos", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const spies = SpyConsole();
    const guard = BrowserGuard.Start({
      ...NetworkOnly,
      Preset: "balanced",
      Notice: { Title: "Esta actividad está siendo monitoreada" },
    });
    const handler = vi.fn();
    guard.On("Threat", handler);

    await window.fetch("https://unknown.example/collect");
    await FlushMicrotasks();

    expect(spies.info).toHaveBeenCalledWith(
      "%cEsta actividad está siendo monitoreada",
      expect.any(String),
    );
    expect(spies.info).toHaveBeenCalledTimes(2);
    expect(spies.group).not.toHaveBeenCalled();
    expect(spies.warn).not.toHaveBeenCalled();
    // El proveedor sigue recibiendo los hallazgos por código.
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("findings: imprime hallazgos y no el aviso", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const spies = SpyConsole();
    BrowserGuard.Start({ ...NetworkOnly, Console: "findings" });
    await window.fetch("https://unknown.example/collect");
    await FlushMicrotasks();
    expect(spies.group).toHaveBeenCalledTimes(1);
    expect(spies.info).not.toHaveBeenCalledWith(
      expect.stringContaining("Security monitoring"),
      expect.anything(),
    );
  });

  it("silent: no escribe nada en consola", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const spies = SpyConsole();
    BrowserGuard.Start({ ...NetworkOnly, Console: "silent" });
    await window.fetch("https://unknown.example/collect");
    await FlushMicrotasks();
    expect(spies.info).not.toHaveBeenCalled();
    expect(spies.group).not.toHaveBeenCalled();
    expect(spies.warn).not.toHaveBeenCalled();
  });

  it("el aviso no se repite al reiniciar", () => {
    const spies = SpyConsole();
    BrowserGuard.Start(NetworkOnly);
    BrowserGuard.Stop();
    BrowserGuard.Start(NetworkOnly);
    expect(spies.info).toHaveBeenCalledTimes(2);
  });
});
