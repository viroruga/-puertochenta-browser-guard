/**
 * Utilidades de URL y orígenes. Todas las funciones son puras y nunca lanzan.
 *
 * Las usan los monitores de red, DOM, CSP y realms para describir destinos sin registrar
 * datos sensibles, los detectores para clasificar orígenes contra la configuración, y la
 * validación de configuración para normalizar los patrones de origen.
 */

/** Esquemas con origen de red comparable. */
const NetworkSchemes = new Set(["http:", "https:", "ws:", "wss:"]);

/** Equivalencias WebSocket → HTTP para comparar orígenes. */
const SchemeEquivalents: Record<string, string> = { "ws:": "http:", "wss:": "https:" };

/**
 * Resultado de clasificar un origen contra la configuración:
 * - same-origin: mismo origen que la página (ws/wss se comparan como http/https).
 * - allowed: coincide con Network.AllowedOrigins (o la lista equivalente).
 * - blocked: coincide con la lista de bloqueados (tiene prioridad sobre todo).
 * - unknown: origen de red que no figura en ninguna lista.
 * - non-network: sin origen de red (data:, blob:, javascript:, ...).
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
 * Retorna la URL sin query string, fragmento ni credenciales (`url.host` no incluye
 * "usuario:clave@"). Los parámetros de consulta pueden contener tokens; nunca se registran.
 */
export function SanitizeUrl(url: URL): string {
  if (!NetworkSchemes.has(url.protocol)) {
    // Para data:, blob:, javascript:, etc. solo se conserva el esquema: el resto de la
    // URL ES el contenido (código, payload, id de blob) y puede contener datos sensibles.
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
 * Retorna el origen en minúsculas (sin ruta), "<esquema>//*.<dominio>" para comodines,
 * o null si el patrón no es válido.
 */
export function NormalizeOriginPattern(pattern: string): string | null {
  const trimmed = pattern.trim().toLowerCase();
  if (trimmed === "") {
    return null;
  }
  // Comodín: "new URL" no acepta "*" en el host, así que se interpreta a mano. Grupos:
  // 1 = esquema con ":", 2 = dominio (hasta la primera "/", que se descarta).
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
 * "https://*.example.com" coincide con cualquier subdominio, a cualquier profundidad,
 * pero no con "https://example.com" ni con "https://evilexample.com".
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
  // El "." previo evita que "evilexample.com" coincida con "*.example.com".
  return host.endsWith(`.${suffix}`);
}

/**
 * Indica si un origen coincide con algún patrón de la lista (ya normalizada con
 * NormalizeOriginPattern). Los orígenes WebSocket también se comparan con su
 * equivalente HTTP, para que permitir "https://api.x.com" cubra "wss://api.x.com".
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
 * Información de destino lista para registrar (ya saneada).
 */
export interface DescribedUrl {
  /** URL saneada (ver SanitizeUrl), o "[invalid-url]" si no se pudo interpretar. */
  Url: string;
  /** Origen de red, o null para esquemas no de red o URLs inválidas. */
  Origin: string | null;
  /** Esquema con ":" ("https:", "data:", ...), o null si la URL es inválida. */
  Scheme: string | null;
  HasQuery: boolean;
  /** Longitud de la query sin el "?": se registra la longitud, nunca el contenido. */
  QueryLength: number;
}

/**
 * Resuelve y sanea una URL arbitraria en relación a `base` (normalmente la URL de la
 * página). Nunca lanza: una URL inválida produce Url "[invalid-url]".
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
