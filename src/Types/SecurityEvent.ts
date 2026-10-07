/**
 * Evento interno normalizado. Los monitores generan eventos; nunca deciden
 * si algo es un ataque.
 */
export interface SecurityEvent<T = unknown> {
  Id: string;
  Timestamp: number;
  Type: string;
  Source: string;
  Data: T;
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
  Url: string;
  Origin: string | null;
  Method?: string;
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
  Src: string | null;
  Origin: string | null;
  Scheme: string | null;
  Inline: boolean;
  InlineLength?: number;
  ParserInserted: boolean;
  Type?: string;
  Async?: boolean;
  Defer?: boolean;
  Integrity?: string;
  CrossOrigin?: string | null;
}

/**
 * Datos de una violación CSP reportada por el navegador.
 */
export interface CspViolationData {
  BlockedUri: string;
  BlockedOrigin: string | null;
  ViolatedDirective: string;
  EffectiveDirective: string;
  SourceFile: string;
  LineNumber: number;
  ColumnNumber: number;
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
  Property: string;
  Change: PrototypeChangeKind;
  ValueType?: string;
  PreviousValueType?: string;
  PreviousLooksNative?: boolean;
  LooksNative?: boolean;
  IsAccessor?: boolean;
}

/**
 * Resultado observacional del análisis de una función.
 */
export interface FunctionAnalysis {
  LooksNative: boolean;
  Confidence: number;
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
  Target: string;
  Phase: RuntimeChangePhase;
  Analysis?: FunctionAnalysis;
}

/**
 * Señales de automatización o de entorno inconsistente observadas en el navegador.
 * Solo contiene nombres de señal (p. ej. "webdriver", "env-software-gl"), nunca los
 * valores leídos, para no construir una huella identificable del usuario.
 */
export interface BotEnvironmentData {
  Phase: "start" | "recheck";
  Signals: string[];
}

/**
 * Motivo por el que InteractionMonitor emite un resumen de actividad.
 */
export type BotActivityReason = "first-interaction" | "synthetic-threshold" | "checkpoint";

/**
 * Resumen de interacción. Solo contadores: nunca teclas, coordenadas ni objetivos.
 */
export interface BotActivityData {
  Reason: BotActivityReason;
  ElapsedMs: number;
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
  Access: "contentWindow" | "contentDocument";
}

/**
 * Sinks de DOM XSS observados.
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
  Length: number;
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
