/**
 * Niveles de severidad soportados, ordenados de menor a mayor.
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/**
 * Lista ordenada de severidades. El índice representa el rango relativo.
 */
export const SeverityLevels: readonly Severity[] = ["info", "low", "medium", "high", "critical"];

/**
 * Retorna el rango numérico de una severidad (0 = info, 4 = critical).
 */
export function SeverityRank(severity: Severity): number {
  return SeverityLevels.indexOf(severity);
}

/**
 * Indica si una severidad alcanza o supera un umbral mínimo.
 */
export function IsSeverityAtLeast(severity: Severity, minimum: Severity): boolean {
  return SeverityRank(severity) >= SeverityRank(minimum);
}
