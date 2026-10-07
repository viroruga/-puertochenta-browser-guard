import { describe, expect, it } from "vitest";
import { AvailablePresets, GetPresetConfig } from "../src/Config/Presets";
import { ConfigLimits, ResolveConfig } from "../src/Config/ResolveConfig";
import type { BrowserGuardConfig } from "../src/Types/BrowserGuardConfig";

describe("ResolveConfig", () => {
  it("usa balanced con valores seguros por defecto", () => {
    const config = ResolveConfig();
    expect(config.Preset).toBe("balanced");
    expect(config.Console).toBe("notice");
    expect(config.Notice.Title).toBe("Security monitoring active");
    expect(config.Risk.MinSeverity).toBe("low");
    expect(config.Forensic.Enabled).toBe(false);
    expect(Object.values(config.Monitors).every(Boolean)).toBe(true);
    expect(config.Network.AllowedOrigins).toEqual([]);
  });

  it("aplica overrides del usuario sobre el preset", () => {
    const config = ResolveConfig({
      Preset: "strict",
      Console: false,
      Monitors: { WebSocket: false },
      Forensic: { Enabled: true, MaxEvents: 50 },
    });
    expect(config.Preset).toBe("strict");
    expect(config.Console).toBe("silent");
    expect(config.Monitors.WebSocket).toBe(false);
    expect(config.Monitors.Fetch).toBe(true);
    expect(config.Forensic).toEqual({ Enabled: true, MaxEvents: 50 });
  });

  it("normaliza y deduplica orígenes, descartando inválidos", () => {
    const config = ResolveConfig({
      Network: {
        AllowedOrigins: [
          "https://API.example.com/v1",
          "https://api.example.com",
          "https://*.cdn.example.com",
          "not a url",
          "",
          42 as unknown as string,
        ],
      },
    });
    expect(config.Network.AllowedOrigins).toEqual([
      "https://api.example.com",
      "https://*.cdn.example.com",
    ]);
  });

  it("limita valores numéricos para evitar memoria ilimitada o polling agresivo", () => {
    const config = ResolveConfig({
      Forensic: { MaxEvents: 10_000_000 },
      History: { MaxFindings: 1 },
      Integrity: { IntervalMs: 1 },
    });
    expect(config.Forensic.MaxEvents).toBe(ConfigLimits.MaxEvents.Max);
    expect(config.History.MaxFindings).toBe(ConfigLimits.MaxFindings.Min);
    expect(config.Integrity.IntervalMs).toBe(ConfigLimits.IntervalMs.Min);
  });

  it("tolera entradas inválidas sin lanzar", () => {
    const invalid = {
      Preset: "nope",
      Console: "yes",
      Forensic: { MaxEvents: Number.NaN },
      Risk: {
        MinSeverity: "extreme",
        Weights: { "network.unknown-origin": "x", "script.inline": 50 },
      },
    } as unknown as BrowserGuardConfig;
    const config = ResolveConfig(invalid);
    expect(config.Preset).toBe("balanced");
    expect(config.Console).toBe("notice");
    expect(config.Forensic.MaxEvents).toBe(1000);
    expect(config.Risk.MinSeverity).toBe("low");
    expect(config.Risk.Weights).toEqual({ "script.inline": 50 });
  });

  it("Console acepta booleanos y modos explícitos", () => {
    expect(ResolveConfig({ Console: true }).Console).toBe("findings");
    expect(ResolveConfig({ Console: false }).Console).toBe("silent");
    expect(ResolveConfig({ Console: "notice", Preset: "development" }).Console).toBe("notice");
    expect(ResolveConfig({ Preset: "development" }).Console).toBe("findings");
  });

  it("Notice permite personalizar título y mensaje, ignorando textos vacíos", () => {
    const config = ResolveConfig({ Notice: { Title: "Monitoreo activo", Message: "  " } });
    expect(config.Notice.Title).toBe("Monitoreo activo");
    expect(config.Notice.Message).toContain("runtime security monitoring");
    expect(ResolveConfig({ Notice: null as never }).Notice.Title).toBe(
      "Security monitoring active",
    );
  });

  it("Risk.Weights no objeto se ignora", () => {
    const config = ResolveConfig({ Risk: { Weights: null as never } });
    expect(config.Risk.Weights).toEqual({});
  });

  it("Risk.MinSeverity también ajusta el umbral de consola", () => {
    const config = ResolveConfig({ Preset: "forensic", Risk: { MinSeverity: "high" } });
    expect(config.Risk.MinSeverity).toBe("high");
    expect(config.ConsoleMinSeverity).toBe("high");
  });
});

describe("Presets", () => {
  it("define los cuatro presets", () => {
    expect(AvailablePresets).toEqual(["development", "balanced", "strict", "forensic"]);
  });

  it("development reporta todo con mucho detalle", () => {
    const config = GetPresetConfig("development");
    expect(config.Risk.MinSeverity).toBe("info");
    expect(config.ConsoleMinSeverity).toBe("info");
  });

  it("strict solo reporta riesgo medio o superior", () => {
    const config = GetPresetConfig("strict");
    expect(config.Risk.MinSeverity).toBe("medium");
    expect(config.ConsoleMinSeverity).toBe("medium");
  });

  it("forensic habilita la línea de tiempo y mantiene la consola moderada", () => {
    const config = GetPresetConfig("forensic");
    expect(config.Forensic).toEqual({ Enabled: true, MaxEvents: 1000 });
    expect(config.Risk.MinSeverity).toBe("info");
    expect(config.ConsoleMinSeverity).toBe("medium");
  });

  it("cada preset retorna una copia independiente", () => {
    const first = GetPresetConfig("balanced");
    first.Network.AllowedOrigins.push("https://mutated.example");
    expect(GetPresetConfig("balanced").Network.AllowedOrigins).toEqual([]);
  });
});
