import type { FindingStatistics, SecurityFinding } from "../Types/SecurityFinding";
import type { Severity } from "../Types/Severity";
import { RingBuffer } from "../Utils/RingBuffer";

/** Contador de FindingStatistics que corresponde a cada severidad. */
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
 * BrowserGuard agrega aquí cada SecurityFinding publicado; alimenta GetReport(),
 * GetStatus().FindingsCount y las estadísticas del snapshot (GuardStore).
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

  /** @param maxFindings Capacidad del buffer (History.MaxFindings). */
  public constructor(maxFindings: number) {
    this.Buffer = new RingBuffer(maxFindings);
  }

  /** Guarda un hallazgo (descartando el más antiguo si está lleno) y actualiza contadores. */
  public Add(finding: SecurityFinding): void {
    this.Buffer.Push(finding);
    this.Statistics.Total++;
    this.Statistics[StatisticKeys[finding.Severity]]++;
  }

  /** Hallazgos retenidos, del más antiguo al más reciente (copia). */
  public GetFindings(): SecurityFinding[] {
    return this.Buffer.ToArray();
  }

  /** Copia de las estadísticas acumuladas: el llamador no puede alterar los contadores. */
  public GetStatistics(): FindingStatistics {
    return { ...this.Statistics };
  }

  /** Cantidad de hallazgos retenidos (no el total histórico; ver Statistics.Total). */
  public get Size(): number {
    return this.Buffer.Size;
  }
}
