/**
 * Análisis de strings que llegan a sinks peligrosos (innerHTML, document.write,
 * setTimeout con código, setAttribute...). Lo usa SinkMonitor para decidir si una
 * escritura merece un evento "dom.sink" y con qué indicadores.
 *
 * Retorna solo NOMBRES de indicadores, nunca fragmentos del contenido: el HTML puede
 * contener datos personales y no debe registrarse.
 *
 * Rendimiento: un prefiltro barato descarta la gran mayoría de los strings antes de
 * ejecutar expresiones regulares, y se analiza como máximo MaxAnalyzedLength caracteres.
 */

/**
 * Indicador de riesgo en contenido destinado a un sink:
 * - script-tag: etiqueta <script>.
 * - auto-event-handler: handler que se ejecuta sin interacción (onerror, onload...).
 * - event-handler: cualquier otro atributo on*.
 * - javascript-url: esquema "javascript:" no trivial (también ofuscado con entidades).
 * - embedded-content: iframe/object/embed/frame/base o srcdoc.
 * - sensitive-access: acceso a cookies/storage o técnicas de exfiltración y ofuscación.
 * - probe: prueba de concepto típica (alert(1), debugger...).
 * - url-reflected: contiene un valor sospechoso de la URL actual (DOM XSS reflejado).
 * - string-code: código pasado como string a setTimeout/setInterval.
 */
export type MarkupIndicator =
  | "script-tag"
  | "auto-event-handler"
  | "event-handler"
  | "javascript-url"
  | "embedded-content"
  | "sensitive-access"
  | "probe"
  | "url-reflected"
  | "string-code";

/**
 * URL de la página, o una función que la obtiene. La función permite leerla solo si
 * hace falta (cuando ya hay indicadores): leer location.href en cada llamada tiene costo.
 */
export type PageHref = string | null | (() => string | null);

/** Caracteres analizados como máximo (los payloads reales son cortos). */
export const MaxAnalyzedLength = 100_000;

/** Longitud mínima de un valor de la URL para considerarlo reflejado. */
const MinReflectedLength = 6;

/**
 * Prefiltro combinado: una sola pasada que descarta el HTML benigno (la inmensa mayoría)
 * antes de ejecutar los análisis individuales.
 */
const MaybeDangerousMarkup =
  /<script|[\s/"']on[a-z]{3,}\s*=|javascript|&#|<(?:iframe|object|embed|frame|base)\b|srcdoc/i;

/** Etiqueta <script> (\b evita coincidir con otras etiquetas que empiezan igual). */
const ScriptTag = /<script\b/i;

/**
 * Handlers que se ejecutan sin interacción del usuario: los de los payloads clásicos.
 * Exige que el atributo esté dentro de una etiqueta ("<img ... onerror=") y precedido de
 * espacio, "/" o comilla, que el parser HTML acepta como separador de atributos.
 */
const AutoEventHandler =
  /<[a-z][^>]*?[\s/"'](on(?:error|load|focus|focusin|animationstart|animationend|transitionend|toggle|begin|pageshow|loadstart|canplay|scroll))\s*=/i;

/** Cualquier atributo on* (3+ letras) dentro de una etiqueta. */
const EventHandler = /<[a-z][^>]*?[\s/"']on[a-z]{3,}\s*=/i;

/**
 * "javascript:" en texto plano o con la "j" codificada como entidad decimal o hexadecimal
 * (ofuscación). Es global (/g) porque HasDangerousJavascript recorre todas las apariciones.
 */
const JavascriptScheme = /(?:javascript|&#0*106;?avascript|&#x0*6a;?avascript)\s*:/gi;

/**
 * Usos inofensivos habituales: href="javascript:void(0)" o "javascript:;". Se evalúa
 * sobre lo que sigue a "javascript:" y debe terminar en comilla, ">" o fin de texto.
 */
const HarmlessJavascript = /^\s*(?:void\s*\(?\s*0\s*\)?\s*;?|;)?\s*(?:["'>]|$)/i;

/** Contenido capaz de cargar otro documento o de cambiar la base de las URLs relativas. */
const EmbeddedContent = /<(?:iframe|object|embed|frame|base)\b|\bsrcdoc\s*=/i;

/** Acceso a datos sensibles o técnicas típicas de exfiltración y ofuscación. */
const SensitiveAccess =
  /document\.cookie|localStorage|sessionStorage|document\.domain|\bfromCharCode\b|\batob\s*\(|\beval\s*\(|new\s+Function\b|navigator\.sendBeacon|new\s+Image\b/i;

/** Pruebas de concepto habituales (alert(1), prompt``...). */
const Probe = /\b(?:alert|prompt|confirm)\s*[(`]|\bdebugger\b/i;

/** Caracteres que hacen sospechoso a un valor de la URL reflejado en un sink. */
const SuspiciousValue = /[<>"'`]|javascript\s*:|on[a-z]{3,}\s*=/i;

/** Atributos cuyo valor es una URL navegable o ejecutable. */
const UrlAttributes: ReadonlySet<string> = new Set([
  "href",
  "src",
  "action",
  "formaction",
  "xlink:href",
  "data",
  "background",
  "poster",
]);

/** Trunca a MaxAnalyzedLength para acotar el costo de las expresiones regulares. */
function Limit(value: string): string {
  return value.length > MaxAnalyzedLength ? value.slice(0, MaxAnalyzedLength) : value;
}

/**
 * Indica si alguna aparición de "javascript:" no es un uso inofensivo. Se revisan todas:
 * un href="javascript:void(0)" no debe ocultar otra aparición con código real.
 */
function HasDangerousJavascript(text: string): boolean {
  // La regex es global y compartida: lastIndex debe reiniciarse en cada llamada.
  JavascriptScheme.lastIndex = 0;
  for (let match = JavascriptScheme.exec(text); match; match = JavascriptScheme.exec(text)) {
    // 40 caracteres alcanzan para reconocer los usos inofensivos, que son cortos.
    const rest = text.slice(match.index + match[0].length, match.index + match[0].length + 40);
    if (!HarmlessJavascript.test(rest)) {
      return true;
    }
  }
  return false;
}

/**
 * Decodifica un valor de query/hash ("+" como espacio). Si la codificación es inválida
 * (decodeURIComponent lanza URIError) retorna el valor sin decodificar.
 */
function SafeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

// Caché de un solo elemento: la URL cambia poco y los sinks se escriben muy seguido.
let CachedHref: string | null = null;
let CachedValues: readonly string[] = [];

/**
 * Valores sospechosos de la URL actual (query y hash), decodificados. Se recalculan
 * solo si la URL cambió. Los valores nunca salen de esta función más que para comparar.
 */
export function SuspiciousUrlValues(href: string | null): readonly string[] {
  if (href === null) {
    return [];
  }
  if (href === CachedHref) {
    return CachedValues;
  }
  const values = new Set<string>();
  const queryStart = href.indexOf("?");
  const hashStart = href.indexOf("#");
  const query =
    queryStart === -1
      ? ""
      : href.slice(queryStart + 1, hashStart > queryStart ? hashStart : undefined);
  const hash = hashStart === -1 ? "" : href.slice(hashStart + 1);

  // Los hash de las SPA suelen tener sus propios "?" y "&" ("#/ruta?x=1&y=2").
  for (const part of `${query}&${hash}`.split(/[&#?]/)) {
    const separator = part.indexOf("=");
    // Se prueba el valor y también el par completo, por si se refleja "clave=valor".
    const candidates = separator === -1 ? [part] : [part.slice(separator + 1), part];
    for (const candidate of candidates) {
      const value = SafeDecode(candidate);
      // Valores cortos o sin caracteres activos coincidirían por azar con HTML legítimo.
      if (value.length >= MinReflectedLength && SuspiciousValue.test(value)) {
        values.add(value);
      }
    }
  }
  CachedHref = href;
  CachedValues = [...values];
  return CachedValues;
}

/**
 * Indicadores comunes a HTML y código: datos sensibles, pruebas y reflejo de la URL.
 */
function ContentIndicators(text: string, pageHref: PageHref): MarkupIndicator[] {
  const indicators: MarkupIndicator[] = [];
  if (SensitiveAccess.test(text)) {
    indicators.push("sensitive-access");
  }
  if (Probe.test(text)) {
    indicators.push("probe");
  }
  const href = typeof pageHref === "function" ? pageHref() : pageHref;
  if (SuspiciousUrlValues(href).some((value) => text.includes(value))) {
    indicators.push("url-reflected");
  }
  return indicators;
}

/**
 * Analiza HTML destinado a un sink (innerHTML, document.write, srcdoc...). Retorna null
 * si no hay estructura ejecutable; los indicadores de contenido (sensitive-access, probe,
 * url-reflected) solo se agregan cuando ya hay al menos uno estructural.
 */
export function AnalyzeMarkup(markup: string, pageHref: PageHref): MarkupIndicator[] | null {
  // Prefiltros: sin "<" ni "javascript"/entidades no puede haber HTML peligroso, y sin
  // ninguna construcción ejecutable no hace falta el análisis detallado.
  if (markup.length < 5 || !/[<]|javascript|&#/i.test(markup)) {
    return null;
  }
  const text = Limit(markup);
  if (!MaybeDangerousMarkup.test(text)) {
    return null;
  }
  const indicators: MarkupIndicator[] = [];
  if (ScriptTag.test(text)) {
    indicators.push("script-tag");
  }
  if (AutoEventHandler.test(text)) {
    indicators.push("auto-event-handler");
  } else if (EventHandler.test(text)) {
    indicators.push("event-handler");
  }
  if (HasDangerousJavascript(text)) {
    indicators.push("javascript-url");
  }
  if (EmbeddedContent.test(text)) {
    indicators.push("embedded-content");
  }
  if (indicators.length === 0) {
    // Sin estructura ejecutable, el resto de los indicadores no aplica a HTML.
    return null;
  }
  return [...indicators, ...ContentIndicators(text, pageHref)];
}

/**
 * Analiza código pasado como string (setTimeout("...")). Siempre es un indicador.
 */
export function AnalyzeCode(code: string, pageHref: PageHref): MarkupIndicator[] {
  return ["string-code", ...ContentIndicators(Limit(code), pageHref)];
}

/**
 * Analiza un atributo asignado con setAttribute. Retorna null si es inofensivo.
 * Los handlers on* siempre se reportan (asignar código como atributo ya es un sink);
 * los atributos de URL, solo con un "javascript:" peligroso.
 */
export function AnalyzeAttribute(
  name: string,
  value: string,
  pageHref: PageHref,
): MarkupIndicator[] | null {
  const attribute = name.toLowerCase();
  if (attribute.startsWith("on") && attribute.length > 4) {
    // Reutiliza la regex de handlers automáticos sobre una etiqueta sintética.
    const auto = AutoEventHandler.test(`<x ${attribute}=`);
    return [
      auto ? "auto-event-handler" : "event-handler",
      ...ContentIndicators(Limit(value), pageHref),
    ];
  }
  if (attribute === "srcdoc") {
    return AnalyzeMarkup(value, pageHref);
  }
  if (UrlAttributes.has(attribute) && HasDangerousJavascript(Limit(value))) {
    return ["javascript-url", ...ContentIndicators(Limit(value), pageHref)];
  }
  return null;
}
