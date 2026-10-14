import type { ResolvedAntiScrapingConfig } from "../Types/BrowserGuardConfig";
import {
  ClampInteger,
  IsPlainObject,
  IsValidHeaderName,
  ResolveEndpoint,
  ResolveBoolean,
  ResolveOrigins,
} from "./ConfigValidators";

/**
 * Valores por defecto y límites del plugin AntiScraping.
 *
 * - MaxRequestsPerMinute: solicitudes hechas por código (fetch/XHR/WebSocket/...) por
 *   minuto a partir de las cuales hay ráfaga. Un mínimo bajo haría que una SPA normal
 *   pareciera un bot.
 * - SequentialThreshold: ids consecutivos (/item/1, /item/2, ...) para considerarlo un
 *   barrido. Con muy pocos se marcaría una navegación "anterior/siguiente" corta.
 * - HeaderName: header con el veredicto que se agrega a las solicitudes propias.
 */
export const AntiScrapingDefaults = {
  MaxRequestsPerMinute: { Min: 10, Max: 10_000, Default: 120 },
  SequentialThreshold: { Min: 3, Max: 1000, Default: 10 },
  ProtectSelector: "[data-guard-protect]",
  Placeholder: "Content unavailable.",
  HeaderName: "X-BrowserGuard-Verdict",
} as const;

/**
 * Acepta el selector solo si el navegador puede interpretarlo. Un selector inválido
 * haría lanzar a querySelectorAll dentro de ContentShield justo al activar la protección.
 */
function ResolveSelector(value: unknown): string {
  if (typeof value !== "string" || value.trim() === "") {
    return AntiScrapingDefaults.ProtectSelector;
  }
  // Sin document (SSR, tests en Node) no se puede validar: se acepta tal cual.
  if (typeof document !== "undefined") {
    // Un fragmento vacío permite probar la sintaxis sin recorrer el documento real.
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
 * explícitamente con Enabled: false. Tolerante como ResolveConfig: nunca lanza.
 *
 * `pageHref` sirve para resolver y validar el endpoint del desafío (por defecto, la URL
 * actual; undefined en SSR).
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
  // Se recorta para acotar lo que se inserta en el DOM. Se inserta como nodo de texto
  // (ContentShield), así que no hay riesgo de inyectar HTML.
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
    // Por defecto solo se protege ante un veredicto "bot": retirar contenido a un usuario
    // real por un veredicto dudoso es peor que dejarlo visible a un scraper.
    ProtectAt: value.ProtectAt === "suspicious" ? "suspicious" : "bot",
    Placeholder: placeholder,
    VerdictHeader: {
      Enabled: ResolveBoolean(header.Enabled, true),
      Name: headerName,
      // Orígenes externos que, además del propio, reciben el header. Vacío = solo el
      // mismo origen, para no revelar el veredicto (ni el id de sesión) a terceros.
      Origins: ResolveOrigins(header.Origins),
    },
    Challenge: ResolveChallenge(value.Challenge, pageHref),
  };
}

/**
 * Valida el endpoint del desafío con las mismas reglas que el envío remoto (https, mismo
 * origen o localhost). Retorna null (sin desafío) si falta o no es válido.
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
