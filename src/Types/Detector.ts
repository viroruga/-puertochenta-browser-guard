import type { RiskSignal } from "../Core/RiskSignals";
import type { SecurityEvent, SecurityEventType } from "./SecurityEvent";
import type { FindingCategory } from "./SecurityFinding";

/**
 * Hallazgo candidato producido por un detector, antes de ser puntuado.
 * El detector describe QUÉ observó y con qué señales; RiskEngine decide la severidad.
 */
export interface FindingCandidate {
  Category: FindingCategory;
  Title: string;
  Description: string;
  Signals: RiskSignal[];
  Evidence?: Record<string, unknown>;
}

/**
 * Contrato común de los detectores.
 */
export interface Detector {
  readonly Name: string;
  /** Tipos de evento que analiza este detector. */
  readonly Handles: readonly SecurityEventType[];
  Analyze(event: SecurityEvent): FindingCandidate | null;
}
