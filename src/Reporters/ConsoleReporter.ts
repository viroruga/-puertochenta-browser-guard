import type { SecurityFinding } from "../Types/SecurityFinding";
import { IsSeverityAtLeast, type Severity } from "../Types/Severity";
import type { Reporter } from "./Reporter";

/** Ventana durante la cual hallazgos equivalentes no se vuelven a imprimir. */
export const DedupeWindowMs = 10_000;

/** Máximo de claves recordadas para deduplicación (memoria acotada). */
const MaxDedupeEntries = 200;

const BannerWidth = 40;

const SeverityStyles: Record<Severity, string> = {
  critical: "background:#b00020;color:#fff;font-weight:bold;padding:1px 6px;border-radius:3px",
  high: "background:#e65100;color:#fff;font-weight:bold;padding:1px 6px;border-radius:3px",
  medium: "background:#f9a825;color:#000;font-weight:bold;padding:1px 6px;border-radius:3px",
  low: "background:#1565c0;color:#fff;padding:1px 6px;border-radius:3px",
  info: "background:#546e7a;color:#fff;padding:1px 6px;border-radius:3px",
};

type ConsoleLike = Pick<
  Console,
  "group" | "groupCollapsed" | "groupEnd" | "error" | "warn" | "info"
>;

interface DedupeEntry {
  LastAt: number;
  Suppressed: number;
}

function Banner(): string {
  const title = " BrowserGuard";
  return [
    `╔${"═".repeat(BannerWidth)}╗`,
    `║${title.padEnd(BannerWidth)}║`,
    `╚${"═".repeat(BannerWidth)}╝`,
  ].join("\n");
}

function ReadEvidenceString(finding: SecurityFinding, key: string): string | null {
  const evidence = finding.Evidence;
  if (typeof evidence !== "object" || evidence === null) {
    return null;
  }
  const value = (evidence as Record<string, unknown>)[key];
  return typeof value === "string" && value !== "" ? value : null;
}

/**
 * Reporter de consola.
 *
 * - critical/high: grupo expandido y console.error.
 * - medium: grupo colapsado y console.warn.
 * - low/info: grupo colapsado y console.info.
 *
 * Para no llenar la consola, respeta un umbral de severidad y suprime hallazgos
 * equivalentes (misma categoría, título y origen) durante DedupeWindowMs,
 * informando cuántos se omitieron en la siguiente impresión.
 */
export class ConsoleReporter implements Reporter {
  public readonly Name = "ConsoleReporter";
  private readonly Recent = new Map<string, DedupeEntry>();

  public constructor(
    private readonly MinSeverity: Severity,
    private readonly Output: ConsoleLike = console,
    private readonly Now: () => number = () => Date.now(),
  ) {}

  public Report(finding: SecurityFinding): void {
    if (!IsSeverityAtLeast(finding.Severity, this.MinSeverity)) {
      return;
    }
    const suppressed = this.Deduplicate(finding);
    if (suppressed === null) {
      return;
    }
    this.Print(finding, suppressed);
  }

  public Dispose(): void {
    this.Recent.clear();
  }

  /**
   * Retorna null si el hallazgo debe suprimirse, o la cantidad suprimida previamente.
   */
  private Deduplicate(finding: SecurityFinding): number | null {
    const key = [
      finding.Category,
      finding.Title,
      ReadEvidenceString(finding, "Origin") ?? ReadEvidenceString(finding, "Target") ?? "",
    ].join("|");
    const now = this.Now();
    const entry = this.Recent.get(key);

    if (entry && now - entry.LastAt < DedupeWindowMs) {
      entry.Suppressed++;
      return null;
    }

    // Reinsertar mantiene el Map ordenado por uso reciente.
    this.Recent.delete(key);
    this.Recent.set(key, { LastAt: now, Suppressed: 0 });
    if (this.Recent.size > MaxDedupeEntries) {
      const oldest = this.Recent.keys().next().value;
      if (oldest !== undefined) {
        this.Recent.delete(oldest);
      }
    }
    return entry?.Suppressed ?? 0;
  }

  private Print(finding: SecurityFinding, suppressed: number): void {
    const severity = finding.Severity.toUpperCase();
    const label = `%cBrowserGuard ${severity}%c ${finding.Title}`;
    const style = SeverityStyles[finding.Severity];
    const expanded = finding.Severity === "critical" || finding.Severity === "high";

    if (expanded) {
      this.Output.group(label, style, "");
    } else {
      this.Output.groupCollapsed(label, style, "");
    }

    try {
      const write = this.SelectWriter(finding.Severity);
      write(this.Format(finding, suppressed));
      if (finding.Evidence !== undefined) {
        write("Evidence:", finding.Evidence);
      }
    } finally {
      this.Output.groupEnd();
    }
  }

  private SelectWriter(severity: Severity): (...data: unknown[]) => void {
    switch (severity) {
      case "critical":
      case "high":
        return (...data) => {
          this.Output.error(...data);
        };
      case "medium":
        return (...data) => {
          this.Output.warn(...data);
        };
      default:
        return (...data) => {
          this.Output.info(...data);
        };
    }
  }

  private Format(finding: SecurityFinding, suppressed: number): string {
    const sections = [
      Banner(),
      `${finding.Severity.toUpperCase()} SECURITY EVENT`,
      `Category:\n${finding.Category}`,
      `${finding.Title}\n${finding.Description}`,
    ];
    const origin = ReadEvidenceString(finding, "Origin");
    if (origin !== null) {
      sections.push(`Origin:\n${origin}`);
    }
    sections.push(`Risk:\n${finding.RiskScore} / 100`);
    if (finding.Stack !== undefined) {
      sections.push(`Stack:\n${finding.Stack}`);
    }
    if (suppressed > 0) {
      sections.push(
        `(${suppressed} similar event(s) suppressed in the last ${DedupeWindowMs / 1000}s)`,
      );
    }
    return sections.join("\n\n");
  }
}
