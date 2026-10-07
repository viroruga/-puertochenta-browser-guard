import type { BotVerdict, SessionAssessment } from "../Types/Bot";
import type { RiskEngine } from "./RiskEngine";
import type { RiskSignal } from "./RiskSignals";

/** Puntajes a partir de los cuales cambia el veredicto. */
export const BotThresholds = { Suspicious: 40, Bot: 70 } as const;

/**
 * Señales que la interacción "humana" no puede compensar:
 * - automatización concluyente: las herramientas pueden generar eventos de entrada
 *   confiables (isTrusted) mediante el protocolo de DevTools;
 * - comportamiento automatizado: mover el mouse no justifica eventos generados por
 *   script ni barridos de URLs.
 * La interacción solo compensa señales pasivas (entorno, falta de interacción).
 */
const UncompensableSignals: ReadonlySet<RiskSignal> = new Set([
  "bot.webdriver",
  "bot.headless",
  "bot.automation-artifact",
  "bot.synthetic-events",
  "bot.sequential-crawl",
  "bot.request-burst",
]);

/**
 * Acumula las señales de bot de la sesión y calcula el veredicto.
 *
 * El puntaje usa los mismos pesos que RiskEngine (configurables con Risk.Weights),
 * sobre el conjunto de señales distintas vistas en la sesión. La interacción humana
 * resta puntaje solo frente a señales pasivas (ver UncompensableSignals). Una vez
 * que la sesión se clasifica como "bot", el veredicto ya no retrocede.
 */
export class BotSession {
  private readonly Signals = new Set<RiskSignal>();
  private Assessment: SessionAssessment = {
    Verdict: "unknown",
    Score: 0,
    Signals: [],
    UpdatedAt: Date.now(),
  };

  public constructor(
    private readonly Engine: RiskEngine,
    private readonly OnChange: (assessment: SessionAssessment) => void,
  ) {}

  /**
   * Incorpora señales. Notifica solo si el veredicto cambió.
   */
  public Add(signals: readonly RiskSignal[]): void {
    const fresh = signals.filter(
      (signal) => signal.startsWith("bot.") && !this.Signals.has(signal),
    );
    if (fresh.length === 0) {
      return;
    }
    for (const signal of fresh) {
      this.Signals.add(signal);
    }

    const previous = this.Assessment.Verdict;
    const uncompensable = [...this.Signals].some((signal) => UncompensableSignals.has(signal));
    const scored = [...this.Signals].filter(
      (signal) => !(uncompensable && signal === "bot.human-interaction"),
    );
    const score = this.Engine.Score(scored);
    this.Assessment = {
      Verdict: previous === "bot" ? "bot" : this.Classify(score),
      Score: score,
      Signals: [...this.Signals],
      UpdatedAt: Date.now(),
    };
    if (this.Assessment.Verdict !== previous) {
      this.OnChange(this.Get());
    }
  }

  public Get(): SessionAssessment {
    return { ...this.Assessment, Signals: [...this.Assessment.Signals] };
  }

  private Classify(score: number): BotVerdict {
    if (score >= BotThresholds.Bot) {
      return "bot";
    }
    if (score >= BotThresholds.Suspicious) {
      return "suspicious";
    }
    return this.Signals.has("bot.human-interaction") ? "human" : "unknown";
  }
}
