import type { ResolvedAntiScrapingConfig } from "../Types/BrowserGuardConfig";
import {
  ClampInteger,
  IsPlainObject,
  IsValidHeaderName,
  ResolveEndpoint,
  ResolveBoolean,
  ResolveOrigins,
} from "./ConfigValidators";

export const AntiScrapingDefaults = {
  MaxRequestsPerMinute: { Min: 10, Max: 10_000, Default: 120 },
  SequentialThreshold: { Min: 3, Max: 1000, Default: 10 },
  ProtectSelector: "[data-guard-protect]",
  Placeholder: "Content unavailable.",
  HeaderName: "X-BrowserGuard-Verdict",
} as const;

/**
 * Acepta el selector solo si el navegador puede interpretarlo.
 */
function ResolveSelector(value: unknown): string {
  if (typeof value !== "string" || value.trim() === "") {
    return AntiScrapingDefaults.ProtectSelector;
  }
  if (typeof document !== "undefined") {
    try {
      document.createDocumentFragment().querySelector(value);
    } catch {
      return AntiScrapingDefaults.ProtectSelector;
    }
  }
  return value;
}

/**
 * Resuelve la configuración del plugin AntiScraping. Retorna null si se desactivó
 * explícitamente con Enabled: false.
 */
export function ResolveAntiScrapingConfig(
  input: unknown = {},
  pageHref: string | undefined = (globalThis as { location?: Location }).location?.href,
): ResolvedAntiScrapingConfig | null {
  const value = IsPlainObject(input) ? input : {};
  if (value.Enabled === false) {
    return null;
  }
  const signals = IsPlainObject(value.Signals) ? value.Signals : {};
  const header = IsPlainObject(value.VerdictHeader) ? value.VerdictHeader : {};
  const headerName =
    typeof header.Name === "string" && IsValidHeaderName(header.Name)
      ? header.Name
      : AntiScrapingDefaults.HeaderName;
  const placeholder =
    typeof value.Placeholder === "string"
      ? value.Placeholder.slice(0, 500)
      : AntiScrapingDefaults.Placeholder;

  return {
    Signals: {
      Automation: ResolveBoolean(signals.Automation, true),
      RequestRate: ResolveBoolean(signals.RequestRate, true),
      Interaction: ResolveBoolean(signals.Interaction, true),
      Environment: ResolveBoolean(signals.Environment, true),
    },
    MaxRequestsPerMinute: ClampInteger(
      value.MaxRequestsPerMinute,
      AntiScrapingDefaults.MaxRequestsPerMinute.Default,
      AntiScrapingDefaults.MaxRequestsPerMinute.Min,
      AntiScrapingDefaults.MaxRequestsPerMinute.Max,
    ),
    SequentialThreshold: ClampInteger(
      value.SequentialThreshold,
      AntiScrapingDefaults.SequentialThreshold.Default,
      AntiScrapingDefaults.SequentialThreshold.Min,
      AntiScrapingDefaults.SequentialThreshold.Max,
    ),
    ProtectSelector: ResolveSelector(value.ProtectSelector),
    ProtectAt: value.ProtectAt === "suspicious" ? "suspicious" : "bot",
    Placeholder: placeholder,
    VerdictHeader: {
      Enabled: ResolveBoolean(header.Enabled, true),
      Name: headerName,
      Origins: ResolveOrigins(header.Origins),
    },
    Challenge: ResolveChallenge(value.Challenge, pageHref),
  };
}

/**
 * Valida el endpoint del desafío con las mismas reglas que el envío remoto.
 */
function ResolveChallenge(
  value: unknown,
  pageHref: string | undefined,
): { Endpoint: string } | null {
  if (!IsPlainObject(value)) {
    return null;
  }
  const endpoint = ResolveEndpoint(value.Endpoint, pageHref);
  return endpoint === null ? null : { Endpoint: endpoint };
}
