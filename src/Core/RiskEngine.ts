import type { FindingCandidate } from "../Types/Detector";
import type { SecurityEvent } from "../Types/SecurityEvent";
import type { SecurityFinding } from "../Types/SecurityFinding";
import { IsSeverityAtLeast, type Severity } from "../Types/Severity";
import { CreateId } from "../Utils/IdGenerator";
import { SafeSerialize } from "../Utils/SafeSerializer";
import { DefaultRiskWeights, type RiskSignal, type RiskWeightOverrides } from "./RiskSignals";

/**
 * Puntaje mínimo para cada severidad, de mayor a menor.
 */
export const SeverityThresholds: readonly { Severity: Severity; MinScore: number }[] = [
  { Severity: "critical", MinScore: 80 },
  { Severity: "high", MinScore: 60 },
  { Severity: "medium", MinScore: 40 },
  { Severity: "low", MinScore: 20 },
  { Severity: "info", MinScore: 0 },
];

export interface RiskAssessment {
  RiskScore: number;
  Severity: Severity;
}

/**
 * Motor de riesgo: traduce señales a un puntaje 0-100 y a una severidad,
 * y construye el SecurityFinding final.
 */
export class RiskEngine {
  private readonly Weights: Record<string, number>;

  public constructor(
    overrides: RiskWeightOverrides = {},
    private readonly MinSeverity: Severity = "info",
  ) {
    this.Weights = { ...DefaultRiskWeights, ...overrides };
  }

  public GetWeight(signal: RiskSignal): number {
    return this.Weights[signal] ?? 0;
  }

  /**
   * Suma los pesos de señales únicas y limita el resultado a 0-100.
   */
  public Score(signals: readonly RiskSignal[]): number {
    let total = 0;
    for (const signal of new Set(signals)) {
      total += this.GetWeight(signal);
    }
    return Math.min(100, Math.max(0, Math.round(total)));
  }

  public SeverityForScore(score: number): Severity {
    for (const threshold of SeverityThresholds) {
      if (score >= threshold.MinScore) {
        return threshold.Severity;
      }
    }
    return "info";
  }

  public Assess(signals: readonly RiskSignal[]): RiskAssessment {
    const score = this.Score(signals);
    return { RiskScore: score, Severity: this.SeverityForScore(score) };
  }

  /**
   * Indica si una severidad supera el umbral configurado.
   */
  public ShouldReport(severity: Severity): boolean {
    return IsSeverityAtLeast(severity, this.MinSeverity);
  }

  /**
   * Evalúa un candidato y construye el hallazgo. Retorna null si no alcanza el umbral.
   * La evidencia se serializa de forma segura para no retener ni filtrar datos sensibles.
   */
  public Evaluate(candidate: FindingCandidate, event: SecurityEvent): SecurityFinding | null {
    const assessment = this.Assess(candidate.Signals);
    if (!this.ShouldReport(assessment.Severity)) {
      return null;
    }

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
    if (candidate.Evidence !== undefined) {
      finding.Evidence = SafeSerialize(candidate.Evidence);
    }
    if (event.Stack !== undefined) {
      finding.Stack = event.Stack;
    }
    return finding;
  }
}
