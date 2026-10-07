import type { FindingStatistics, SecurityFinding } from "../Types/SecurityFinding";
import type { Severity } from "../Types/Severity";
import { RingBuffer } from "../Utils/RingBuffer";

const StatisticKeys: Record<Severity, Exclude<keyof FindingStatistics, "Total">> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/**
 * Historial acotado de hallazgos.
 *
 * Los hallazgos se guardan en un ring buffer (memoria constante); las estadísticas
 * son acumulativas desde Start(), incluso para hallazgos ya descartados del buffer.
 */
export class FindingHistory {
  private readonly Buffer: RingBuffer<SecurityFinding>;
  private readonly Statistics: FindingStatistics = {
    Total: 0,
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };

  public constructor(maxFindings: number) {
    this.Buffer = new RingBuffer(maxFindings);
  }

  public Add(finding: SecurityFinding): void {
    this.Buffer.Push(finding);
    this.Statistics.Total++;
    this.Statistics[StatisticKeys[finding.Severity]]++;
  }

  public GetFindings(): SecurityFinding[] {
    return this.Buffer.ToArray();
  }

  public GetStatistics(): FindingStatistics {
    return { ...this.Statistics };
  }

  public get Size(): number {
    return this.Buffer.Size;
  }
}
