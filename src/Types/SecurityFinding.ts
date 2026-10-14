import type { Severity } from "./Severity";

/**
 * Tipos públicos de los hallazgos: lo que RiskEngine produce y reciben los reporters, los
 * manejadores de eventos y GetReport().
 */

/**
 * Categorías de hallazgos:
 * - network: destino de red desconocido, bloqueado, inseguro o con patrón de exfiltración.
 * - script-injection: <script> insertado desde un origen no permitido o dinámicamente.
 * - prototype-pollution: cambios en prototipos nativos.
 * - runtime-integrity: funciones críticas reemplazadas o acceso al realm de un iframe.
 * - csp: violaciones de Content Security Policy.
 * - dom: <iframe>, <object> o <embed> insertados dinámicamente o de origen no permitido.
 * - xss: contenido con indicadores de XSS escrito en un sink peligroso.
 * - bot: automatización o scraping (plugin AntiScraping).
 */
export type FindingCategory =
  | "network"
  | "script-injection"
  | "prototype-pollution"
  | "runtime-integrity"
  | "csp"
  | "dom"
  | "xss"
  | "bot";

/**
 * Hallazgo de seguridad evaluado por RiskEngine.
 */
export interface SecurityFinding {
  /** Id local ("finding-..."). */
  Id: string;
  /** Momento del evento que lo originó (no del análisis), en ms desde epoch. */
  Timestamp: number;
  Category: FindingCategory;
  /** Derivada de RiskScore por RiskEngine. */
  Severity: Severity;
  /** Título corto en inglés. */
  Title: string;
  Description: string;
  /** Puntaje de riesgo entre 0 y 100. */
  RiskScore: number;
  /** Señales que contribuyeron al puntaje. */
  Signals: string[];
  /** Identificador del evento que originó el hallazgo. */
  EventId: string;
  /** Datos de contexto, ya pasados por SafeSerialize (acotados y censurados). */
  Evidence?: unknown;
  /** Stack limpio de quien originó la acción, si se capturó. */
  Stack?: string;
}

/**
 * Estadísticas acumuladas de hallazgos: total y conteo por severidad.
 */
export interface FindingStatistics {
  Total: number;
  Critical: number;
  High: number;
  Medium: number;
  Low: number;
  Info: number;
}

/**
 * Reporte retornado por GetReport().
 */
export interface GuardReport {
  /** Inicio del monitoreo, en ms desde epoch. */
  StartedAt: number;
  Findings: SecurityFinding[];
  Statistics: FindingStatistics;
}
