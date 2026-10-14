import { SeverityLevels, type Severity } from "../Types/Severity";
import { NormalizeOriginPattern, ParseUrl } from "../Utils/UrlUtils";

/**
 * Validadores tolerantes: ante un valor inválido retornan el valor por defecto
 * en lugar de lanzar excepciones.
 *
 * Por qué tolerantes: la configuración llega desde JavaScript sin tipos (o desde JSON),
 * y un error de configuración no debe impedir que BrowserGuard arranque ni romper la
 * aplicación que lo incluye. Lo inválido se descarta en silencio y se usa el default.
 */

/**
 * Redondea un número al entero más cercano y lo limita a [min, max]. Si no es un número
 * finito retorna `fallback`. Los límites evitan memoria ilimitada o polling agresivo.
 */
export function ClampInteger(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.round(value)));
}

/**
 * Acepta solo booleanos reales: "false" (string) o 0 no se interpretan, para no
 * desactivar un monitor por un valor ambiguo.
 */
export function ResolveBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

/** Acepta solo una severidad conocida (info, low, medium, high, critical). */
export function ResolveSeverity(value: unknown, fallback: Severity): Severity {
  return SeverityLevels.includes(value as Severity) ? (value as Severity) : fallback;
}

/** Objeto literal utilizable como diccionario: excluye null y arreglos. */
export function IsPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Normaliza una lista de orígenes descartando entradas inválidas y duplicadas.
 * Cada entrada se reduce a su origen ("https://a.com/ruta" → "https://a.com") o a un
 * comodín de subdominio ("https://*.a.com"); ver NormalizeOriginPattern.
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

/**
 * Indica si `name` es un nombre de header válido. Se valida antes de usarlo porque
 * Headers/setRequestHeader lanzan con nombres inválidos, y un header roto haría fallar
 * las solicitudes de la aplicación o el envío de hallazgos.
 */
export function IsValidHeaderName(name: string): boolean {
  return HeaderNamePattern.test(name);
}

/**
 * Hosts de loopback aceptados por http (desarrollo local). URL normaliza el hostname,
 * por eso IPv6 aparece entre corchetes.
 */
const LocalHosts: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Valida el endpoint. Solo se aceptan destinos que no expongan los hallazgos en
 * texto plano por la red: https, el mismo origen que la página, o localhost.
 *
 * Las URLs relativas se resuelven contra `pageHref`. Retorna la URL absoluta sin
 * fragmento, o null si no es aceptable (quien la llama desactiva entonces el envío
 * remoto o el desafío).
 */
export function ResolveEndpoint(value: unknown, pageHref?: string): string | null {
  if (typeof value !== "string" || value.trim() === "") {
    return null;
  }
  const url = ParseUrl(value.trim(), pageHref);
  // Credenciales en la URL quedarían expuestas en logs, historial y headers: se rechazan.
  if (!url || url.username !== "" || url.password !== "") {
    return null;
  }
  const pageOrigin = pageHref ? ParseUrl(pageHref)?.origin : undefined;
  const isSecure = url.protocol === "https:";
  // Mismo origen: hereda el transporte de la página (p. ej. un sitio http en una intranet);
  // enviar por http no expone nada que la propia página no exponga ya.
  const isSameOrigin = pageOrigin !== undefined && url.origin === pageOrigin;
  // Loopback por http: el tráfico no sale de la máquina (desarrollo local).
  const isLocal = url.protocol === "http:" && LocalHosts.has(url.hostname);
  if (!isSecure && !isSameOrigin && !isLocal) {
    return null;
  }
  url.hash = "";
  return url.href;
}
