/**
 * Utilidades de URL y orígenes. Todas las funciones son puras y nunca lanzan.
 */

/** Esquemas con origen de red comparable. */
const NetworkSchemes = new Set(["http:", "https:", "ws:", "wss:"]);

/** Equivalencias WebSocket → HTTP para comparar orígenes. */
const SchemeEquivalents: Record<string, string> = { "ws:": "http:", "wss:": "https:" };

/**
 * Resultado de clasificar un origen contra la configuración.
 */
export type OriginClassification =
  "same-origin" | "allowed" | "blocked" | "unknown" | "non-network";

/**
 * Intenta construir una URL absoluta. Retorna null si no es válida.
 */
export function ParseUrl(input: string, base?: string): URL | null {
  try {
    return new URL(input, base);
  } catch {
    return null;
  }
}

/**
 * Retorna la URL sin query string, fragmento ni credenciales.
 * Los parámetros de consulta pueden contener tokens; nunca se registran.
 */
export function SanitizeUrl(url: URL): string {
  if (!NetworkSchemes.has(url.protocol)) {
    // Para data:, blob:, javascript:, etc. solo se conserva el esquema.
    return `${url.protocol}[redacted]`;
  }
  return `${url.protocol}//${url.host}${url.pathname}`;
}

/**
 * Retorna el origen de una URL de red o null si no aplica.
 */
export function GetOrigin(url: URL): string | null {
  return NetworkSchemes.has(url.protocol) ? `${url.protocol}//${url.host}` : null;
}

/**
 * Normaliza un patrón de origen configurado por el usuario.
 * Acepta "https://example.com", "https://example.com/ruta" o "https://*.example.com".
 */
export function NormalizeOriginPattern(pattern: string): string | null {
  const trimmed = pattern.trim().toLowerCase();
  if (trimmed === "") {
    return null;
  }
  const wildcard = /^([a-z][a-z0-9+.-]*:)\/\/\*\.([^/]+)/.exec(trimmed);
  if (wildcard) {
    return `${wildcard[1] ?? ""}//*.${wildcard[2] ?? ""}`;
  }
  const url = ParseUrl(trimmed);
  return url ? GetOrigin(url) : null;
}

/**
 * Convierte un origen ws/wss a su equivalente http/https.
 */
function ToHttpEquivalent(origin: string): string {
  for (const [scheme, equivalent] of Object.entries(SchemeEquivalents)) {
    if (origin.startsWith(`${scheme}//`)) {
      return equivalent + origin.slice(scheme.length);
    }
  }
  return origin;
}

/**
 * Compara un origen contra un patrón normalizado (exacto o comodín de subdominio).
 */
function MatchesPattern(origin: string, pattern: string): boolean {
  if (origin === pattern) {
    return true;
  }
  const wildcard = /^([a-z][a-z0-9+.-]*:)\/\/\*\.(.+)$/.exec(pattern);
  if (!wildcard) {
    return false;
  }
  const scheme = wildcard[1] ?? "";
  const suffix = wildcard[2] ?? "";
  if (!origin.startsWith(`${scheme}//`)) {
    return false;
  }
  const host = origin.slice(scheme.length + 2);
  return host.endsWith(`.${suffix}`);
}

/**
 * Indica si un origen coincide con algún patrón de la lista.
 * Los orígenes WebSocket también se comparan con su equivalente HTTP.
 */
export function MatchesAnyOrigin(origin: string, patterns: readonly string[]): boolean {
  const normalized = origin.toLowerCase();
  const equivalent = ToHttpEquivalent(normalized);
  return patterns.some(
    (pattern) => MatchesPattern(normalized, pattern) || MatchesPattern(equivalent, pattern),
  );
}

/**
 * Indica si dos orígenes son equivalentes (considerando ws ↔ http).
 */
export function IsSameOrigin(origin: string, pageOrigin: string): boolean {
  return ToHttpEquivalent(origin.toLowerCase()) === ToHttpEquivalent(pageOrigin.toLowerCase());
}

/**
 * Clasifica un origen de destino. Los bloqueados tienen prioridad sobre todo.
 */
export function ClassifyOrigin(
  origin: string | null,
  pageOrigin: string,
  allowed: readonly string[],
  blocked: readonly string[],
): OriginClassification {
  if (origin === null) {
    return "non-network";
  }
  if (MatchesAnyOrigin(origin, blocked)) {
    return "blocked";
  }
  if (IsSameOrigin(origin, pageOrigin)) {
    return "same-origin";
  }
  if (MatchesAnyOrigin(origin, allowed)) {
    return "allowed";
  }
  return "unknown";
}

/**
 * Indica si un destino degrada el transporte de una página segura (https → http/ws).
 */
export function IsInsecureTransport(url: URL, pageProtocol: string): boolean {
  return pageProtocol === "https:" && (url.protocol === "http:" || url.protocol === "ws:");
}

/**
 * Información de destino lista para registrar.
 */
export interface DescribedUrl {
  Url: string;
  Origin: string | null;
  Scheme: string | null;
  HasQuery: boolean;
  QueryLength: number;
}

/**
 * Resuelve y sanea una URL arbitraria en relación a la página.
 */
export function DescribeUrl(raw: string, base: string): DescribedUrl {
  const url = ParseUrl(raw, base);
  if (!url) {
    return { Url: "[invalid-url]", Origin: null, Scheme: null, HasQuery: false, QueryLength: 0 };
  }
  return {
    Url: SanitizeUrl(url),
    Origin: GetOrigin(url),
    Scheme: url.protocol,
    HasQuery: url.search !== "",
    QueryLength: Math.max(0, url.search.length - 1),
  };
}
