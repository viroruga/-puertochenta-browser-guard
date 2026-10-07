import type { RiskWeightOverrides } from "../Core/RiskSignals";
import type { Reporter } from "../Reporters/Reporter";
import type { GuardPlugin } from "./Plugin";
import type { Severity } from "./Severity";

/**
 * Presets disponibles.
 */
export type GuardPreset = "development" | "balanced" | "strict" | "forensic";

/**
 * Qué se muestra en la consola del navegador.
 * - silent: nada.
 * - notice: solo un aviso de que la página está monitoreada (recomendado en producción:
 *   el usuario final no ve los hallazgos).
 * - findings: cada hallazgo con su detalle (pensado para desarrollo).
 */
export type ConsoleMode = "silent" | "notice" | "findings";

/**
 * Texto del aviso mostrado en modo "notice".
 */
export interface ConsoleNoticeText {
  Title: string;
  Message: string;
}

/**
 * Valores primitivos permitidos como metadatos del reporte remoto.
 */
export type RemoteMetadataValue = string | number | boolean;

/**
 * Configuración del plugin RemoteReporting: envío de hallazgos a un endpoint propio.
 */
export interface RemoteConfig {
  /**
   * URL que recibe los hallazgos por POST. Debe ser https, del mismo origen que la
   * página o http://localhost. Si es inválida, el envío remoto queda deshabilitado.
   */
  Endpoint: string;
  /** Severidad mínima a enviar. Por defecto: "low". */
  MinSeverity?: Severity;
  /** Hallazgos por lote (1 - 100). Por defecto: 20. */
  BatchSize?: number;
  /** Espera máxima antes de enviar un lote incompleto, en ms (1000 - 60000). Por defecto: 5000. */
  FlushIntervalMs?: number;
  /** Hallazgos retenidos en cola como máximo (10 - 5000). Por defecto: 200. */
  MaxQueue?: number;
  /** Reintentos de un lote ante errores transitorios (0 - 10). Por defecto: 3. */
  MaxRetries?: number;
  /**
   * Headers adicionales (p. ej. una clave de ingesta). Visibles en el cliente:
   * no uses secretos. Con headers, el envío al cerrar la página usa fetch keepalive
   * en lugar de sendBeacon.
   */
  Headers?: Record<string, string>;
  /** Metadatos agregados a cada envío (versión de la app, entorno, ...). */
  Metadata?: Record<string, RemoteMetadataValue>;
  /** Incluir stack traces. Por defecto: true. */
  IncludeStack?: boolean;
  /** Incluir evidencia (ya saneada). Por defecto: true. */
  IncludeEvidence?: boolean;
  /** Incluir la ruta de la página (sin query). Por defecto: true. */
  IncludePagePath?: boolean;
}

/**
 * Configuración remota resuelta.
 */
export interface ResolvedRemoteConfig {
  Endpoint: string;
  MinSeverity: Severity;
  BatchSize: number;
  FlushIntervalMs: number;
  MaxQueue: number;
  MaxRetries: number;
  Headers: Record<string, string>;
  Metadata: Record<string, RemoteMetadataValue>;
  IncludeStack: boolean;
  IncludeEvidence: boolean;
  IncludePagePath: boolean;
}

/**
 * Configuración del plugin AntiScraping.
 *
 * Detecta navegadores automatizados y comportamiento de bot en el cliente. No puede
 * detener scrapers que no ejecutan JavaScript (curl, requests, Scrapy): para eso se
 * necesita protección en el servidor, que el header de veredicto ayuda a implementar.
 */
export interface AntiScrapingConfig {
  /** Permite desactivar el plugin sin quitarlo (p. ej. en tests end-to-end). Por defecto: true. */
  Enabled?: boolean;
  Signals?: {
    /** navigator.webdriver, headless, rastros de Selenium/Puppeteer/Playwright... */
    Automation?: boolean;
    /** Ráfagas y barridos secuenciales de URLs. */
    RequestRate?: boolean;
    /** Presencia de interacción humana y eventos sintéticos (solo contadores). */
    Interaction?: boolean;
    /** Inconsistencias del entorno (renderizado por software, idiomas, ventana...). */
    Environment?: boolean;
  };
  /** Solicitudes por minuto a partir de las cuales se considera ráfaga (10 - 10000). Por defecto: 120. */
  MaxRequestsPerMinute?: number;
  /** Solicitudes consecutivas con id incremental para considerar barrido (3 - 1000). Por defecto: 10. */
  SequentialThreshold?: number;
  /** Selector de los elementos cuyo contenido se protege. Por defecto: "[data-guard-protect]". */
  ProtectSelector?: string;
  /** Veredicto a partir del cual se oculta el contenido protegido. Por defecto: "bot". */
  ProtectAt?: "suspicious" | "bot";
  /** Texto que reemplaza al contenido protegido. */
  Placeholder?: string;
  /** Header con el veredicto agregado a las solicitudes (fetch y XHR). */
  VerdictHeader?: {
    /** Por defecto: true. */
    Enabled?: boolean;
    /** Por defecto: "X-BrowserGuard-Verdict". */
    Name?: string;
    /**
     * Orígenes adicionales al propio que reciben el header. Un header personalizado
     * hacia otro origen dispara un preflight CORS: ese servidor debe permitirlo.
     */
    Origins?: string[];
  };
}

/**
 * Configuración anti-scraping resuelta.
 */
export interface ResolvedAntiScrapingConfig {
  Signals: {
    Automation: boolean;
    RequestRate: boolean;
    Interaction: boolean;
    Environment: boolean;
  };
  MaxRequestsPerMinute: number;
  SequentialThreshold: number;
  ProtectSelector: string;
  ProtectAt: "suspicious" | "bot";
  Placeholder: string;
  VerdictHeader: { Enabled: boolean; Name: string; Origins: string[] };
}

/**
 * Monitores que pueden habilitarse o deshabilitarse.
 */
export interface MonitorToggles {
  Fetch?: boolean;
  Xhr?: boolean;
  WebSocket?: boolean;
  Dom?: boolean;
  Csp?: boolean;
  Prototype?: boolean;
  /** Verificación periódica de funciones críticas del runtime. */
  Runtime?: boolean;
}

/**
 * Configuración pública de BrowserGuard. Todas las propiedades son opcionales;
 * los valores faltantes se completan con el preset seleccionado.
 */
export interface BrowserGuardConfig {
  Preset?: GuardPreset;

  /**
   * Salida en consola. `true` equivale a "findings" y `false` a "silent".
   * Por defecto: "findings" en development y "notice" en los demás presets.
   */
  Console?: boolean | ConsoleMode;

  /** Personaliza el aviso del modo "notice". */
  Notice?: Partial<ConsoleNoticeText>;

  Monitors?: MonitorToggles;

  Network?: {
    /** Orígenes permitidos. Admite comodín de subdominio: "https://*.example.com". */
    AllowedOrigins?: string[];
    /** Orígenes bloqueados (solo se detectan y reportan; no se bloquean). */
    BlockedOrigins?: string[];
  };

  Dom?: {
    /** Orígenes desde los que se esperan scripts. El origen propio siempre se permite. */
    AllowedScriptOrigins?: string[];
  };

  Forensic?: {
    Enabled?: boolean;
    /** Tamaño máximo de la línea de tiempo (ring buffer). */
    MaxEvents?: number;
  };

  History?: {
    /** Cantidad máxima de hallazgos almacenados. */
    MaxFindings?: number;
  };

  Integrity?: {
    /** Intervalo de verificación de prototipos y funciones críticas, en ms. */
    IntervalMs?: number;
  };

  Risk?: {
    /** Severidad mínima para registrar y emitir un hallazgo. */
    MinSeverity?: Severity;
    /** Sobrescritura de pesos de señales de riesgo. */
    Weights?: RiskWeightOverrides;
  };

  /** Reporters propios (SIEM, analítica, ...). Reciben cada hallazgo emitido. */
  Reporters?: Reporter[];

  /**
   * Funciones opcionales, importadas desde rutas separadas del paquete:
   * - AntiScraping() de "@puertochenta/browser-guard/anti-scraping";
   * - RemoteReporting() de "@puertochenta/browser-guard/remote".
   */
  Plugins?: GuardPlugin[];
}

/**
 * Configuración completa luego de aplicar preset y valores por defecto.
 */
export interface ResolvedConfig {
  Preset: GuardPreset;
  Console: ConsoleMode;
  ConsoleMinSeverity: Severity;
  Notice: ConsoleNoticeText;
  Monitors: Required<MonitorToggles>;
  Network: {
    AllowedOrigins: string[];
    BlockedOrigins: string[];
  };
  Dom: {
    AllowedScriptOrigins: string[];
  };
  Forensic: {
    Enabled: boolean;
    MaxEvents: number;
  };
  History: {
    MaxFindings: number;
  };
  Integrity: {
    IntervalMs: number;
  };
  Risk: {
    MinSeverity: Severity;
    Weights: RiskWeightOverrides;
  };
  Stack: {
    MaxFrames: number;
  };
}
