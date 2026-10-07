import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { ResetGuard } from "./Helpers";

describe("BrowserGuard ciclo de vida", () => {
  afterEach(() => {
    ResetGuard();
  });

  it("Start retorna una instancia en ejecución", () => {
    const guard = BrowserGuard.Start({ Console: false });
    expect(guard.IsRunning()).toBe(true);
    expect(BrowserGuard.GetInstance()).toBe(guard);
    expect(guard.GetStatus().Supported).toBe(true);
  });

  it("Start es idempotente: retorna la instancia existente", () => {
    const first = BrowserGuard.Start({ Console: false, Preset: "strict" });
    const second = BrowserGuard.Start({ Preset: "development" });
    expect(second).toBe(first);
    expect(second.GetStatus().Preset).toBe("strict");
  });

  it("Stop detiene y libera la instancia activa", () => {
    const guard = BrowserGuard.Start({ Console: false });
    BrowserGuard.Stop();
    expect(guard.IsRunning()).toBe(false);
    expect(guard.GetStatus().StoppedAt).not.toBeNull();
    expect(BrowserGuard.GetInstance()).toBeNull();
  });

  it("Stop es seguro de llamar varias veces", () => {
    const guard = BrowserGuard.Start({ Console: false });
    guard.Stop();
    expect(() => {
      guard.Stop();
      BrowserGuard.Stop();
    }).not.toThrow();
  });

  it("después de Stop, Start crea una instancia nueva", () => {
    const first = BrowserGuard.Start({ Console: false });
    first.Stop();
    const second = BrowserGuard.Start({ Console: false });
    expect(second).not.toBe(first);
    expect(second.IsRunning()).toBe(true);
  });

  it("la API estática sin instancia activa es inocua", () => {
    const unsubscribe = BrowserGuard.On("Threat", vi.fn());
    expect(() => {
      unsubscribe();
      BrowserGuard.Off("Threat", vi.fn());
    }).not.toThrow();
    expect(BrowserGuard.GetReport()).toBeNull();
    expect(BrowserGuard.GetStatus()).toBeNull();
    expect(BrowserGuard.GetTimeline()).toEqual([]);
  });

  it("GetReport retorna un reporte vacío al iniciar", () => {
    const guard = BrowserGuard.Start({ Console: false });
    const report = guard.GetReport();
    expect(report.Findings).toEqual([]);
    expect(report.Statistics).toEqual({
      Total: 0,
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Info: 0,
    });
    expect(report.StartedAt).toBeLessThanOrEqual(Date.now());
    expect(BrowserGuard.GetReport()).toEqual(report);
  });

  it("GetConfig retorna una copia de la configuración efectiva", () => {
    const guard = BrowserGuard.Start({ Console: false, Preset: "forensic" });
    const config = guard.GetConfig();
    config.Forensic.Enabled = false;
    expect(guard.GetConfig().Forensic.Enabled).toBe(true);
  });
});
