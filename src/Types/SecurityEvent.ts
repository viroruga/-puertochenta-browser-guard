/**
 * Tipos de los eventos internos: lo que los monitores observan y los detectores
 * analizan. Ningún payload contiene contenido de la página ni datos del usuario: solo
 * URLs saneadas, longitudes, nombres de señal y metadatos.
 */

/**
 * Evento interno normalizado. Los monitores generan eventos; nunca deciden
 * si algo es un ataque.
 */
export interface SecurityEvent<T = unknown> {
  /** Id local ("evt-..."), referenciado por SecurityFinding.EventId. */
  Id: string;
  /** Momento de la observación, en ms desde epoch. */
  Timestamp: number;
  /** Clave de SecurityEventDataMap (p. ej. "network.request"). */
  Type: string;
  /** Nombre del monitor que lo emitió (p. ej. "FetchMonitor"). */
  Source: string;
  /** Payload según Type. */
  Data: T;
  /** Stack limpio de quien originó la acción, si el monitor lo captura. */
  Stack?: string;
}

/**
 * Mecanismo de red observado.
 */
export type NetworkTransport =
  | "fetch"
  | "xhr"
  | "websocket"
  | "beacon"
  | "eventsource"
  | "form"
  | "window-open"
  | "resource"
  | "service-worker";

/**
 * Datos de una solicitud de red saliente.
 * La URL se almacena sin query string ni fragmento para evitar registrar tokens.
 */
export interface NetworkRequestData {
  Transport: NetworkTransport;
  /** URL saneada (ver SanitizeUrl). */
  Url: string;
  /** Origen de destino, o null para esquemas que no son de red. */
  Origin: string | null;
  /** Método HTTP, cuando se conoce (fetch, xhr, formularios). */
  Method?: string;
  /** Subprotocolos solicitados (solo websocket). */
  Protocols?: string[];
  HasQuery: boolean;
  /**
   * Longitud de la query string (0 si no tiene). Solo la longitud: una query muy larga
   * hacia un origen desconocido es un patrón típico de exfiltración (?c=<cookies>).
   */
  QueryLength: number;
  /** Tipo de recurso informado por el navegador (img, css, link, ...), para "resource". */
  InitiatorType?: string;
}

/**
 * Etiquetas de elementos observadas por DomMonitor.
 */
export type ObservedTagName = "script" | "iframe" | "object" | "embed";

/**
 * Datos de un elemento sensible insertado en el DOM.
 * Para scripts inline solo se registra la longitud del contenido, nunca el texto.
 */
export interface DomElementData {
  TagName: ObservedTagName;
  /** URL saneada del recurso (`data` en <object>, `src` en el resto), o null si no tiene. */
  Src: string | null;
  Origin: string | null;
  /** Esquema de Src ("https:", "data:", "blob:", ...). */
  Scheme: string | null;
  /** Sin URL de origen: contenido embebido en el propio elemento. */
  Inline: boolean;
  /** Longitud del código de un script inline o del srcdoc de un iframe (nunca el texto). */
  InlineLength?: number;
  /**
   * Aproximación: el documento aún se estaba parseando (readyState "loading"). Un script
   * que inserte elementos durante la carga también queda marcado así.
   */
  ParserInserted: boolean;
  /** Atributo type (p. ej. "module"). Este y los siguientes, solo para <script>. */
  Type?: string;
  Async?: boolean;
  Defer?: boolean;
  /** Atributo integrity (SRI), si lo tiene. */
  Integrity?: string;
  /** Atributo crossorigin. */
  CrossOrigin?: string | null;
}

/**
 * Datos de una violación CSP reportada por el navegador.
 */
export interface CspViolationData {
  /** Recurso bloqueado, saneado si es URL; si no, la palabra clave ("inline", "eval"). */
  BlockedUri: string;
  BlockedOrigin: string | null;
  ViolatedDirective: string;
  /** Directiva que realmente se aplicó (p. ej. script-src-elem por fallback). */
  EffectiveDirective: string;
  /** Archivo que provocó la violación, saneado. */
  SourceFile: string;
  LineNumber: number;
  ColumnNumber: number;
  /** "enforce" (se bloqueó) o "report" (Content-Security-Policy-Report-Only). */
  Disposition: string;
}

/**
 * Prototipos nativos monitoreados.
 */
export type MonitoredPrototype =
  | "Object.prototype"
  | "Array.prototype"
  | "Function.prototype"
  | "String.prototype"
  | "Promise.prototype";

/**
 * Tipo de cambio detectado en un prototipo.
 */
export type PrototypeChangeKind = "added" | "removed" | "modified";

/**
 * Datos de un cambio en un prototipo nativo.
 */
export interface PrototypeChangeData {
  Target: MonitoredPrototype;
  /** Nombre de la propiedad (los símbolos, como texto). */
  Property: string;
  Change: PrototypeChangeKind;
  /** typeof del valor nuevo, o "accessor" si es getter/setter (nunca el valor). */
  ValueType?: string;
  /** Igual que ValueType, para el valor anterior ("modified" y "removed"). */
  PreviousValueType?: string;
  /** El valor anterior parecía una función nativa (ver AnalyzeFunction). */
  PreviousLooksNative?: boolean;
  /** El valor nuevo parece una función nativa (ver AnalyzeFunction). */
  LooksNative?: boolean;
  /** La propiedad es un getter/setter (técnica común para interceptar lecturas). */
  IsAccessor?: boolean;
}

/**
 * Resultado observacional del análisis de una función.
 */
export interface FunctionAnalysis {
  /** Veredicto: la función parece la implementación nativa del navegador. */
  LooksNative: boolean;
  /** Confianza en el veredicto, entre 0 y 1 (dos decimales). */
  Confidence: number;
  /**
   * Señales en contra de que sea nativa: "non-native-source", "own-tostring-override",
   * "unexpected-prototype", "name-mismatch", "tostring-tampered", "not-a-function".
   */
  Signals: string[];
}

/**
 * Fase en la que se detectó la modificación del runtime.
 * - baseline: la función ya parecía modificada al iniciar BrowserGuard.
 * - change: la referencia cambió después de iniciar.
 * - removed: la función dejó de existir.
 */
export type RuntimeChangePhase = "baseline" | "change" | "removed";

/**
 * Datos de una modificación de una función crítica del runtime.
 */
export interface RuntimeModificationData {
  /** Función vigilada, p. ej. "window.fetch" o "XMLHttpRequest.prototype.send". */
  Target: string;
  Phase: RuntimeChangePhase;
  /** Análisis de la función actual (ausente en "removed"). */
  Analysis?: FunctionAnalysis;
}

/**
 * Señales de automatización o de entorno inconsistente observadas en el navegador.
 * Solo contiene nombres de señal (p. ej. "webdriver", "env-software-gl"), nunca los
 * valores leídos, para no construir una huella identificable del usuario.
 */
export interface BotEnvironmentData {
  /** Comprobación inicial o periódica (algunas herramientas se inyectan tarde). */
  Phase: "start" | "recheck";
  /** Ver DetectAutomationSignals y DetectEnvironmentSignals. */
  Signals: string[];
}

/**
 * Motivo por el que InteractionMonitor emite un resumen de actividad:
 * - first-interaction: primera interacción confiable de la sesión (sin contar scroll).
 * - synthetic-threshold: se acumularon demasiados eventos sintéticos.
 * - checkpoint: resumen a los 10 s, 30 s y 60 s.
 */
export type BotActivityReason = "first-interaction" | "synthetic-threshold" | "checkpoint";

/**
 * Resumen de interacción. Solo contadores: nunca teclas, coordenadas ni objetivos.
 */
export interface BotActivityData {
  Reason: BotActivityReason;
  /** Tiempo desde que se inició InteractionMonitor, en ms. */
  ElapsedMs: number;
  /** Cantidad de eventos confiables (isTrusted) de cada tipo. */
  Pointer: number;
  Keyboard: number;
  Scroll: number;
  Touch: number;
  /** Eventos de entrada generados por scripts (isTrusted === false). */
  Untrusted: number;
  /** La pestaña está visible (una pestaña en segundo plano no recibe interacción). */
  Visible: boolean;
}

/**
 * Acceso de un script al realm de un iframe del mismo origen.
 */
export interface RealmAccessData {
  /** Origen del iframe: "about:blank", "srcdoc" o la URL saneada. */
  Frame: string;
  /** Propiedad por la que se obtuvo el realm. */
  Access: "contentWindow" | "contentDocument";
}

/**
 * Sinks de DOM XSS observados. href, src, action, formAction y data son asignaciones
 * directas de propiedades de URL (a.href = "javascript:...").
 */
export type SinkName =
  | "innerHTML"
  | "outerHTML"
  | "insertAdjacentHTML"
  | "document.write"
  | "createContextualFragment"
  | "srcdoc"
  | "setAttribute"
  | "setTimeout"
  | "setInterval"
  | "href"
  | "src"
  | "action"
  | "formAction"
  | "data";

/**
 * Escritura de contenido con indicadores de riesgo en un sink peligroso.
 * Nunca incluye el contenido: solo el sink, el elemento, la longitud y los indicadores.
 */
export interface SinkData {
  Sink: SinkName;
  /** Etiqueta del elemento afectado (o del atributo, para setAttribute). */
  Target: string | null;
  /** Longitud del contenido escrito (nunca el contenido). */
  Length: number;
  /** Ver MarkupIndicator. */
  Indicators: string[];
}

/**
 * Mapa de tipos de evento a su payload. Permite un EventBus tipado.
 */
export interface SecurityEventDataMap {
  "network.request": NetworkRequestData;
  "dom.element-inserted": DomElementData;
  "csp.violation": CspViolationData;
  "prototype.changed": PrototypeChangeData;
  "runtime.modified": RuntimeModificationData;
  "bot.environment": BotEnvironmentData;
  "bot.activity": BotActivityData;
  "dom.sink": SinkData;
  "runtime.realm": RealmAccessData;
}

/** Clave de un tipo de evento interno ("network.request", "dom.sink", ...). */
export type SecurityEventType = keyof SecurityEventDataMap;

/**
 * Evento tipado según su clave.
 */
export type TypedSecurityEvent<K extends SecurityEventType> = SecurityEvent<
  SecurityEventDataMap[K]
> & { Type: K };

/**
 * Mapa usado por el EventBus interno: tipo de evento → evento completo.
 */
export type InternalEventMap = {
  [K in SecurityEventType]: TypedSecurityEvent<K>;
};
