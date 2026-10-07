/**
 * Veredicto de la sesión respecto a automatización / scraping.
 * - unknown: sin evidencia suficiente todavía.
 * - human: se observó interacción humana y no hay señales relevantes.
 * - suspicious: señales moderadas (puntaje 40-69).
 * - bot: señales fuertes (puntaje ≥ 70).
 */
export type BotVerdict = "unknown" | "human" | "suspicious" | "bot";

/**
 * Evaluación actual de la sesión.
 */
export interface BotAssessment {
  Verdict: BotVerdict;
  /** Puntaje acumulado 0-100. */
  Score: number;
  /** Señales observadas durante la sesión. */
  Signals: string[];
  UpdatedAt: number;
}
