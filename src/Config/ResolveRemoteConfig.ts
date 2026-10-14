import type { RemoteMetadataValue, ResolvedRemoteConfig } from "../Types/BrowserGuardConfig";
import {
  ClampInteger,
  ResolveEndpoint,
  IsPlainObject,
  IsValidHeaderName,
  ResolveBoolean,
  ResolveSeverity,
} from "./ConfigValidators";

/**
 * Límites del envío remoto. Acotan memoria, tamaño de payload y frecuencia.
 *
 * - BatchSize: hallazgos por envío.
 * - FlushIntervalMs: espera máxima antes de enviar un lote incompleto.
 * - MaxQueue: hallazgos pendientes en memoria; si el backend no responde, se descartan
 *   los más antiguos en lugar de crecer sin límite.
 * - MaxRetries: reintentos por lote ante errores de red o del servidor.
 * - MaxHeaders / MaxMetadataKeys / MaxMetadataLength: acotan lo que se agrega a cada
 *   envío.
 */
export const RemoteLimits = {
  BatchSize: { Min: 1, Max: 100, Default: 20 },
  FlushIntervalMs: { Min: 1000, Max: 60_000, Default: 5000 },
  MaxQueue: { Min: 10, Max: 5000, Default: 200 },
  MaxRetries: { Min: 0, Max: 10, Default: 3 },
  MaxHeaders: 10,
  MaxMetadataKeys: 20,
  MaxMetadataLength: 200,
} as const;

/**
 * Headers propios para el envío (p. ej. una API key). Descarta nombres inválidos y
 * valores con CR/LF: Headers lanzaría con ellos, y rechazarlos también cierra la puerta a
 * inyectar headers adicionales.
 */
function ResolveHeaders(value: unknown): Record<string, string> {
  const headers: Record<string, string> = {};
  if (!IsPlainObject(value)) {
    return headers;
  }
  // El límite se aplica antes de filtrar: entradas inválidas también consumen cupo.
  for (const [name, header] of Object.entries(value).slice(0, RemoteLimits.MaxHeaders)) {
    if (IsValidHeaderName(name) && typeof header === "string" && !/[\r\n]/.test(header)) {
      headers[name] = header;
    }
  }
  return headers;
}

/**
 * Metadatos fijos que acompañan cada envío (versión de la app, entorno, ...). Solo valores
 * primitivos serializables; los strings se recortan para acotar el tamaño del payload.
 */
function ResolveMetadata(value: unknown): Record<string, RemoteMetadataValue> {
  const metadata: Record<string, RemoteMetadataValue> = {};
  if (!IsPlainObject(value)) {
    return metadata;
  }
  for (const [key, entry] of Object.entries(value).slice(0, RemoteLimits.MaxMetadataKeys)) {
    if (typeof entry === "string") {
      metadata[key] = entry.slice(0, RemoteLimits.MaxMetadataLength);
    } else if (
      typeof entry === "boolean" ||
      (typeof entry === "number" && Number.isFinite(entry))
    ) {
      metadata[key] = entry;
    }
  }
  return metadata;
}

/**
 * Resuelve la configuración remota. Retorna null (envío deshabilitado) si no hay
 * configuración o el endpoint no es válido. Nunca lanza.
 *
 * El endpoint debe ser https, del mismo origen que la página o localhost (ver
 * ResolveEndpoint): los hallazgos describen la seguridad del sitio y no deben viajar en
 * texto plano. `pageHref` resuelve endpoints relativos (por defecto, la URL actual).
 */
export function ResolveRemoteConfig(
  value: unknown,
  pageHref: string | undefined = (globalThis as { location?: Location }).location?.href,
): ResolvedRemoteConfig | null {
  if (!IsPlainObject(value)) {
    return null;
  }
  const endpoint = ResolveEndpoint(value.Endpoint, pageHref);
  if (endpoint === null) {
    return null;
  }
  const limits = RemoteLimits;
  return {
    Endpoint: endpoint,
    MinSeverity: ResolveSeverity(value.MinSeverity, "low"),
    BatchSize: ClampInteger(
      value.BatchSize,
      limits.BatchSize.Default,
      limits.BatchSize.Min,
      limits.BatchSize.Max,
    ),
    FlushIntervalMs: ClampInteger(
      value.FlushIntervalMs,
      limits.FlushIntervalMs.Default,
      limits.FlushIntervalMs.Min,
      limits.FlushIntervalMs.Max,
    ),
    MaxQueue: ClampInteger(
      value.MaxQueue,
      limits.MaxQueue.Default,
      limits.MaxQueue.Min,
      limits.MaxQueue.Max,
    ),
    MaxRetries: ClampInteger(
      value.MaxRetries,
      limits.MaxRetries.Default,
      limits.MaxRetries.Min,
      limits.MaxRetries.Max,
    ),
    Headers: ResolveHeaders(value.Headers),
    Metadata: ResolveMetadata(value.Metadata),
    // Opt-out de privacidad: permiten no enviar el stack, la evidencia o la ruta de la
    // página si el backend no los necesita.
    IncludeStack: ResolveBoolean(value.IncludeStack, true),
    IncludeEvidence: ResolveBoolean(value.IncludeEvidence, true),
    IncludePagePath: ResolveBoolean(value.IncludePagePath, true),
  };
}
