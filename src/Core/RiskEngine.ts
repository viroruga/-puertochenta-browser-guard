import type { FindingCandidate } from "../Types/Detector";
import type { SecurityEvent } from "../Types/SecurityEvent";
import type { SecurityFinding } from "../Types/SecurityFinding";
import { IsSeverityAtLeast, type Severity } from "../Types/Severity";
import { CreateId } from "../Utils/IdGenerator";
import { SafeSerialize } from "../Utils/SafeSerializer";
import { DefaultRiskWeights, type RiskSignal, type RiskWeightOverrides } from "./RiskSignals";

/**
 * Puntaje mínimo para cada severidad, de mayor a menor (el orden importa:
 * SeverityForScore se queda con el primer umbral alcanzado).
 */
export const SeverityThresholds: readonly { Severity: Severity; MinScore: number }[] = [
  { Severity: "critical", MinScore: 80 },
  { Severity: "high", MinScore: 60 },
  { Severity: "medium", MinScore: 40 },
  { Severity: "low", MinScore: 20 },
  { Severity: "info", MinScore: 0 },
];

/** Resultado de puntuar un conjunto de señales. */
export interface RiskAssessment {
  RiskScore: number;
  Severity: Severity;
}

/**
 * Motor de riesgo: traduce señales a un puntaje 0-100 y a una severidad,
 * y construye el SecurityFinding final.
 *
 * Posición en el flujo: Detectors → FindingCandidate (señales) → RiskEngine →
 * SecurityFinding. Lo usan BrowserGuard (para cada candidato), BotSession (solo
 * Score, para el veredicto de bot) y los plugins a través de PluginHost.Engine.
 *
 * Es determinista y sin estado más allá de la tabla de pesos: el mismo conjunto de
 * señales produce siempre el mismo puntaje.
 */
export class RiskEngine {
  /** Pesos por defecto combinados con los de la configuración (Risk.Weights). */
  private readonly Weights: Record<string, number>;

  public constructor(
    overrides: RiskWeightOverrides = {},
    private readonly MinSeverity: Severity = "info",
  ) {
    this.Weights = { ...DefaultRiskWeights, ...overrides };
  }

  /** Peso de una señal; 0 si no es conocida (p. ej. una señal de un plugin sin peso). */
  public GetWeight(signal: RiskSignal): number {
    return this.Weights[signal] ?? 0;
  }

  /**
   * Suma los pesos de señales únicas y limita el resultado a 0-100.
   * Las señales repetidas cuentan una sola vez: un detector que repite un nombre
   * no debe inflar la severidad.
   */
  public Score(signals: readonly RiskSignal[]): number {
    let total = 0;
    for (const signal of new Set(signals)) {
      total += this.GetWeight(signal);
    }
    return Math.min(100, Math.max(0, Math.round(total)));
  }

  /** Severidad que corresponde a un puntaje según SeverityThresholds. */
  public SeverityForScore(score: number): Severity {
    for (const threshold of SeverityThresholds) {
      if (score >= threshold.MinScore) {
        return threshold.Severity;
      }
    }
    return "info";
  }

  /** Puntaje y severidad de un conjunto de señales. */
  public Assess(signals: readonly RiskSignal[]): RiskAssessment {
    const score = this.Score(signals);
    return { RiskScore: score, Severity: this.SeverityForScore(score) };
  }

  /**
   * Indica si una severidad alcanza (es igual o mayor que) el umbral Risk.MinSeverity.
   */
  public ShouldReport(severity: Severity): boolean {
    return IsSeverityAtLeast(severity, this.MinSeverity);
  }

  /**
   * Evalúa un candidato y construye el hallazgo. Retorna null si no alcanza el umbral.
   * La evidencia se serializa de forma segura para no retener ni filtrar datos sensibles.
   *
   * @param candidate Resultado de un detector (categoría, textos, señales y evidencia).
   * @param event Evento que originó el candidato: aporta timestamp, id y stack.
   */
  public Evaluate(candidate: FindingCandidate, event: SecurityEvent): SecurityFinding | null {
    const assessment = this.Assess(candidate.Signals);
    if (!this.ShouldReport(assessment.Severity)) {
      return null;
    }

    // El timestamp es el del evento (cuándo ocurrió), no el del análisis (cuándo se procesó).
    const finding: SecurityFinding = {
      Id: CreateId("finding"),
      Timestamp: event.Timestamp,
      Category: candidate.Category,
      Severity: assessment.Severity,
      Title: candidate.Title,
      Description: candidate.Description,
      RiskScore: assessment.RiskScore,
      Signals: [...new Set(candidate.Signals)],
      EventId: event.Id,
    };
    // Las propiedades opcionales se omiten en lugar de asignarse undefined: el hallazgo
    // (y su JSON en los reporters) solo contiene lo que realmente existe.
    if (candidate.Evidence !== undefined) {
      finding.Evidence = SafeSerialize(candidate.Evidence);
    }
    if (event.Stack !== undefined) {
      finding.Stack = event.Stack;
    }
    return finding;
  }
}
