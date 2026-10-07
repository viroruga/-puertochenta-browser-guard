/**
 * Veredicto de la sesión respecto a automatización / scraping.
 * - unknown: sin evidencia suficiente todavía.
 * - human: se observó interacción humana y no hay señales relevantes.
 * - suspicious: señales moderadas (puntaje 40-69).
 * - bot: señales fuertes (puntaje ≥ 70).
 */
export type BotVerdict = "unknown" | "human" | "suspicious" | "bot";

/**
 * Estado de la prueba de trabajo del desafío del servidor:
 * - disabled: no se configuró AntiScraping({ Challenge });
 * - pending: obteniendo o resolviendo el desafío;
 * - ready: la prueba se envía en el header de veredicto;
 * - failed: el endpoint no respondió correctamente (se reintenta).
 */
export type ProofState = "disabled" | "pending" | "ready" | "failed";

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
  Proof: ProofState;
}

/** Evaluación calculada a partir de las señales (sin el estado de la prueba). */
export type SessionAssessment = Omit<BotAssessment, "Proof">;
