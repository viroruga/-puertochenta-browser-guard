import type { ConsoleNoticeText, GuardPreset, ResolvedConfig } from "../Types/BrowserGuardConfig";

/**
 * Aviso por defecto del modo "notice". Describe con precisión lo que se monitorea
 * (comportamiento de seguridad de la página, no la actividad personal del usuario)
 * e incluye la advertencia clásica contra self-XSS.
 */
export const DefaultNotice: ConsoleNoticeText = {
  Title: "Security monitoring active",
  Message:
    "This page is protected by runtime security monitoring. Suspicious activity is detected and reported to the site owner. Do not paste or run code here that you do not understand: it could give others access to your account.",
};

/**
 * Valores base compartidos por todos los presets (equivalen a "balanced").
 * Todos los monitores habilitados, sin listas de orígenes y sin modo forense.
 * Crea objetos nuevos en cada llamada: GetPresetConfig los modifica sin riesgo de
 * contaminar otros presets.
 */
function CreateBaseConfig(preset: GuardPreset): ResolvedConfig {
  return {
    Preset: preset,
    Console: "notice",
    ConsoleMinSeverity: "low",
    Notice: { ...DefaultNotice },
    Monitors: {
      Fetch: true,
      Xhr: true,
      WebSocket: true,
      Dom: true,
      Csp: true,
      Prototype: true,
      Runtime: true,
      Sinks: true,
      Channels: true,
      Realms: true,
    },
    Services: [],
    Learning: { Enabled: false },
    Network: { AllowedOrigins: [], BlockedOrigins: [] },
    Dom: { AllowedScriptOrigins: [] },
    Forensic: { Enabled: false, MaxEvents: 1000 },
    History: { MaxFindings: 500 },
    Integrity: { IntervalMs: 5000, TrustedWrapperMarkers: [] },
    Risk: { MinSeverity: "low", Weights: {} },
    Stack: { MaxFrames: 8 },
  };
}

/**
 * Construye la configuración completa correspondiente a un preset.
 *
 * - development: máximo detalle, incluye hallazgos informativos y los muestra en la
 *   consola (modo "findings"); verificación de integridad más frecuente.
 * - balanced: recomendado para uso general; omite hallazgos informativos y la consola
 *   solo muestra el aviso (modo "notice").
 * - strict: solo comportamientos relevantes o de riesgo elevado (medium+).
 * - forensic: registra todo, guarda la línea de tiempo de eventos (Forensic) y más
 *   historial; la consola solo mostraría riesgo medio o superior para no saturarla.
 *
 * Fuera de development la consola queda en "notice": cualquier usuario puede abrirla, y
 * listar los hallazgos le mostraría a un atacante qué se detecta.
 */
export function GetPresetConfig(preset: GuardPreset): ResolvedConfig {
  const config = CreateBaseConfig(preset);

  switch (preset) {
    case "development":
      config.Console = "findings";
      config.Risk.MinSeverity = "info";
      config.ConsoleMinSeverity = "info";
      config.Integrity.IntervalMs = 2000;
      config.Stack.MaxFrames = 12;
      break;
    case "balanced":
      break;
    case "strict":
      config.Risk.MinSeverity = "medium";
      config.ConsoleMinSeverity = "medium";
      config.Integrity.IntervalMs = 3000;
      break;
    case "forensic":
      config.Risk.MinSeverity = "info";
      config.ConsoleMinSeverity = "medium";
      config.Forensic = { Enabled: true, MaxEvents: 1000 };
      config.History.MaxFindings = 2000;
      config.Integrity.IntervalMs = 2000;
      config.Stack.MaxFrames = 16;
      break;
  }

  return config;
}

/** Preset usado cuando no se indica uno o el indicado no existe. */
export const DefaultPreset: GuardPreset = "balanced";

/** Presets válidos, para validar la entrada del usuario. */
export const AvailablePresets: readonly GuardPreset[] = [
  "development",
  "balanced",
  "strict",
  "forensic",
];
