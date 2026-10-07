import { SeverityLevels, type Severity } from "../Types/Severity";
import { NormalizeOriginPattern, ParseUrl } from "../Utils/UrlUtils";

/**
 * Validadores tolerantes: ante un valor inválido retornan el valor por defecto
 * en lugar de lanzar excepciones.
 */

export function ClampInteger(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.round(value)));
}

export function ResolveBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

export function ResolveSeverity(value: unknown, fallback: Severity): Severity {
  return SeverityLevels.includes(value as Severity) ? (value as Severity) : fallback;
}

export function IsPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Normaliza una lista de orígenes descartando entradas inválidas y duplicadas.
 */
export function ResolveOrigins(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const result = new Set<string>();
  for (const entry of value) {
    const normalized = typeof entry === "string" ? NormalizeOriginPattern(entry) : null;
    if (normalized !== null) {
      result.add(normalized);
    }
  }
  return [...result];
}

/** Nombre de header válido según RFC 7230 (token). */
const HeaderNamePattern = /^[!#$%&'*+.^_`|~0-9a-z-]+$/i;

export function IsValidHeaderName(name: string): boolean {
  return HeaderNamePattern.test(name);
}

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
