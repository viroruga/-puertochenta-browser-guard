import type {
  BrowserGuardConfig,
  ConsoleMode,
  ConsoleNoticeText,
  GuardPreset,
  ResolvedConfig,
} from "../Types/BrowserGuardConfig";
import { ClampInteger, ResolveBoolean, ResolveOrigins, ResolveSeverity } from "./ConfigValidators";
import { AvailablePresets, DefaultPreset, GetPresetConfig } from "./Presets";
import { ExpandServices, MergeOrigins, ResolveServices } from "./Services";

/**
 * Límites de seguridad para valores numéricos configurables.
 * Evitan crecimiento ilimitado de memoria (MaxEvents, MaxFindings) o polling agresivo
 * (IntervalMs de la verificación de integridad).
 */
export const ConfigLimits = {
  MaxEvents: { Min: 10, Max: 100_000 },
  MaxFindings: { Min: 10, Max: 100_000 },
  IntervalMs: { Min: 500, Max: 600_000 },
} as const;

/** Modos de consola válidos. */
const ConsoleModes: readonly ConsoleMode[] = ["silent", "notice", "findings"];

/**
 * Acepta un modo explícito o un booleano (true = findings, false = silent).
 */
function ResolveConsoleMode(value: unknown, fallback: ConsoleMode): ConsoleMode {
  if (typeof value === "boolean") {
    return value ? "findings" : "silent";
  }
  return ConsoleModes.includes(value as ConsoleMode) ? (value as ConsoleMode) : fallback;
}

/**
 * Usa los textos del usuario si son strings no vacíos; si no, los del preset.
 */
function ResolveNotice(value: unknown, fallback: ConsoleNoticeText): ConsoleNoticeText {
  const notice = (typeof value === "object" && value !== null ? value : {}) as Record<
    string,
    unknown
  >;
  const pick = (key: keyof ConsoleNoticeText): string => {
    const text = notice[key];
    return typeof text === "string" && text.trim() !== "" ? text : fallback[key];
  };
  return { Title: pick("Title"), Message: pick("Message") };
}

/** Preset indicado si existe; si no, DefaultPreset ("balanced"). */
function ResolvePreset(value: unknown): GuardPreset {
  return AvailablePresets.includes(value as GuardPreset) ? (value as GuardPreset) : DefaultPreset;
}

/**
 * Filtra pesos personalizados dejando solo números finitos. No valida los nombres de
 * señal ni el rango: un nombre desconocido simplemente no se usa, y los pesos negativos
 * son válidos (restan riesgo, como "csp.report-only").
 */
function ResolveWeights(value: unknown): ResolvedConfig["Risk"]["Weights"] {
  if (typeof value !== "object" || value === null) {
    return {};
  }
  const weights: Record<string, number> = {};
  for (const [key, weight] of Object.entries(value)) {
    if (typeof weight === "number" && Number.isFinite(weight)) {
      weights[key] = weight;
    }
  }
  return weights;
}

/**
 * Combina la configuración del usuario con el preset elegido.
 * Es tolerante a entradas inválidas: nunca lanza excepciones.
 *
 * Orden de precedencia: valor válido del usuario > valor del preset. Las listas de
 * orígenes del usuario se completan con las que aportan los servicios declarados.
 */
export function ResolveConfig(config: BrowserGuardConfig = {}): ResolvedConfig {
  const base = GetPresetConfig(ResolvePreset(config.Preset));
  const monitors = config.Monitors ?? {};
  const services = ResolveServices(config.Services);
  const contributed = ExpandServices(services);

  return {
    Preset: base.Preset,
    Console: ResolveConsoleMode(config.Console, base.Console),
    // No hay opción propia para la consola: si el usuario fija Risk.MinSeverity, la
    // consola lo sigue; si no, usa el valor del preset (p. ej. medium en forensic).
    ConsoleMinSeverity: ResolveSeverity(config.Risk?.MinSeverity, base.ConsoleMinSeverity),
    Notice: ResolveNotice(config.Notice, base.Notice),
    Monitors: {
      Fetch: ResolveBoolean(monitors.Fetch, base.Monitors.Fetch),
      Xhr: ResolveBoolean(monitors.Xhr, base.Monitors.Xhr),
      WebSocket: ResolveBoolean(monitors.WebSocket, base.Monitors.WebSocket),
      Dom: ResolveBoolean(monitors.Dom, base.Monitors.Dom),
      Csp: ResolveBoolean(monitors.Csp, base.Monitors.Csp),
      Prototype: ResolveBoolean(monitors.Prototype, base.Monitors.Prototype),
      Runtime: ResolveBoolean(monitors.Runtime, base.Monitors.Runtime),
      Sinks: ResolveBoolean(monitors.Sinks, base.Monitors.Sinks),
      Channels: ResolveBoolean(monitors.Channels, base.Monitors.Channels),
      Realms: ResolveBoolean(monitors.Realms, base.Monitors.Realms),
    },
    Services: services,
    Learning: {
      Enabled: ResolveBoolean(config.Learning?.Enabled, base.Learning.Enabled),
    },
    Network: {
      AllowedOrigins: MergeOrigins(
        ResolveOrigins(config.Network?.AllowedOrigins),
        contributed.Network,
      ),
      // Los servicios nunca aportan orígenes bloqueados: solo los define el usuario.
      BlockedOrigins: ResolveOrigins(config.Network?.BlockedOrigins),
    },
    Dom: {
      AllowedScriptOrigins: MergeOrigins(
        ResolveOrigins(config.Dom?.AllowedScriptOrigins),
        contributed.Scripts,
      ),
    },
    Forensic: {
      Enabled: ResolveBoolean(config.Forensic?.Enabled, base.Forensic.Enabled),
      MaxEvents: ClampInteger(
        config.Forensic?.MaxEvents,
        base.Forensic.MaxEvents,
        ConfigLimits.MaxEvents.Min,
        ConfigLimits.MaxEvents.Max,
      ),
    },
    History: {
      MaxFindings: ClampInteger(
        config.History?.MaxFindings,
        base.History.MaxFindings,
        ConfigLimits.MaxFindings.Min,
        ConfigLimits.MaxFindings.Max,
      ),
    },
    Integrity: {
      IntervalMs: ClampInteger(
        config.Integrity?.IntervalMs,
        base.Integrity.IntervalMs,
        ConfigLimits.IntervalMs.Min,
        ConfigLimits.IntervalMs.Max,
      ),
      // Solo de servicios declarados: las marcas son falsificables, así que no se aceptan
      // marcas arbitrarias desde la configuración.
      TrustedWrapperMarkers: contributed.WrapperMarkers,
    },
    Risk: {
      MinSeverity: ResolveSeverity(config.Risk?.MinSeverity, base.Risk.MinSeverity),
      Weights: ResolveWeights(config.Risk?.Weights),
    },
    // La profundidad del stack no es configurable: la define el preset.
    Stack: { ...base.Stack },
  };
}
