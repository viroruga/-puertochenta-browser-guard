import type { RemoteMetadataValue, ResolvedRemoteConfig } from "../Types/BrowserGuardConfig";
import { ParseUrl } from "../Utils/UrlUtils";
import {
  ClampInteger,
  IsPlainObject,
  IsValidHeaderName,
  ResolveBoolean,
  ResolveSeverity,
} from "./ConfigValidators";

/**
 * Límites del envío remoto. Acotan memoria, tamaño de payload y frecuencia.
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

const LocalHosts: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Valida el endpoint. Solo se aceptan destinos que no expongan los hallazgos en
 * texto plano por la red: https, el mismo origen que la página, o localhost.
 */
export function ResolveEndpoint(value: unknown, pageHref?: string): string | null {
  if (typeof value !== "string" || value.trim() === "") {
    return null;
  }
  const url = ParseUrl(value.trim(), pageHref);
  if (!url || url.username !== "" || url.password !== "") {
    return null;
  }
  const pageOrigin = pageHref ? ParseUrl(pageHref)?.origin : undefined;
  const isSecure = url.protocol === "https:";
  const isSameOrigin = pageOrigin !== undefined && url.origin === pageOrigin;
  const isLocal = url.protocol === "http:" && LocalHosts.has(url.hostname);
  if (!isSecure && !isSameOrigin && !isLocal) {
    return null;
  }
  url.hash = "";
  return url.href;
}

function ResolveHeaders(value: unknown): Record<string, string> {
  const headers: Record<string, string> = {};
  if (!IsPlainObject(value)) {
    return headers;
  }
  for (const [name, header] of Object.entries(value).slice(0, RemoteLimits.MaxHeaders)) {
    if (IsValidHeaderName(name) && typeof header === "string" && !/[\r\n]/.test(header)) {
      headers[name] = header;
    }
  }
  return headers;
}

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
    IncludeStack: ResolveBoolean(value.IncludeStack, true),
    IncludeEvidence: ResolveBoolean(value.IncludeEvidence, true),
    IncludePagePath: ResolveBoolean(value.IncludePagePath, true),
  };
}
