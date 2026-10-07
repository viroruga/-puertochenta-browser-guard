import type { Severity } from "./Severity";

/**
 * Categorías de hallazgos.
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
  Id: string;
  Timestamp: number;
  Category: FindingCategory;
  Severity: Severity;
  Title: string;
  Description: string;
  /** Puntaje de riesgo entre 0 y 100. */
  RiskScore: number;
  /** Señales que contribuyeron al puntaje. */
  Signals: string[];
  /** Identificador del evento que originó el hallazgo. */
  EventId: string;
  Evidence?: unknown;
  Stack?: string;
}

/**
 * Estadísticas acumuladas de hallazgos.
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
  StartedAt: number;
  Findings: SecurityFinding[];
  Statistics: FindingStatistics;
}
