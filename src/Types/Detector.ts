import type { RiskSignal } from "../Core/RiskSignals";
import type { SecurityEvent, SecurityEventType } from "./SecurityEvent";
import type { FindingCategory } from "./SecurityFinding";

/**
 * Hallazgo candidato producido por un detector, antes de ser puntuado.
 * El detector describe QUÉ observó y con qué señales; RiskEngine decide la severidad.
 */
export interface FindingCandidate {
  Category: FindingCategory;
  /** Título corto en inglés (también se usa para deduplicar en consola). */
  Title: string;
  /** Explicación legible de lo observado. */
  Description: string;
  /** Señales de riesgo observadas; RiskEngine suma sus pesos para el puntaje. */
  Signals: RiskSignal[];
  /** Datos de contexto; RiskEngine los pasa por SafeSerialize antes de publicarlos. */
  Evidence?: Record<string, unknown>;
}

/**
 * Contrato común de los detectores: reciben eventos del EventBus interno y deciden si
 * constituyen un hallazgo. Deben ser rápidos: se ejecutan con cada evento que manejan.
 */
export interface Detector {
  readonly Name: string;
  /** Tipos de evento que analiza este detector. */
  readonly Handles: readonly SecurityEventType[];
  /** Retorna un candidato, o null si el evento no es sospechoso. */
  Analyze(event: SecurityEvent): FindingCandidate | null;
}
