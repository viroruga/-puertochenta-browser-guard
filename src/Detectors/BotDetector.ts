import type { RiskSignal } from "../Core/RiskSignals";
import { SyntheticEventThreshold } from "../Monitors/InteractionMonitor";
import type { ResolvedAntiScrapingConfig } from "../Types/BrowserGuardConfig";
import type { Detector, FindingCandidate } from "../Types/Detector";
import type {
  BotActivityData,
  BotEnvironmentData,
  NetworkRequestData,
  NetworkTransport,
  SecurityEvent,
} from "../Types/SecurityEvent";
import { RequestPatternTracker } from "./RequestPatternTracker";

/**
 * Canales que no reflejan solicitudes hechas por código (una página con muchas imágenes
 * no es una ráfaga de scraping): no cuentan para el ritmo de solicitudes.
 */
const PassiveTransports: ReadonlySet<NetworkTransport> = new Set([
  "resource",
  "form",
  "window-open",
  "service-worker",
]);

/**
 * Tiempo sin ninguna interacción (con la pestaña visible) que se considera señal.
 * Es generoso a propósito: un usuario real puede leer un rato sin tocar nada, pero
 * rara vez pasa medio minuto sin mover el puntero, hacer scroll ni teclear.
 */
export const NoInteractionAfterMs = 30_000;

/**
 * Traduce los nombres de señal de AutomationMonitor a señales de riesgo. Los nombres
 * desconocidos se ignoran (null) en lugar de inventar una señal sin peso definido.
 */
function MapEnvironmentSignal(name: string): RiskSignal | null {
  if (name === "webdriver") {
    return "bot.webdriver";
  }
  if (name === "headless") {
    return "bot.headless";
  }
  if (name.startsWith("artifact:")) {
    return "bot.automation-artifact";
  }
  switch (name) {
    case "env-software-gl":
      return "bot.env-software-gl";
    case "env-no-languages":
      return "bot.env-no-languages";
    case "env-zero-window":
      return "bot.env-zero-window";
    case "env-ua-mismatch":
      return "bot.env-ua-mismatch";
    case "env-no-plugins":
      return "bot.env-no-plugins";
    default:
      return null;
  }
}

/**
 * Detecta automatización y comportamiento de scraping.
 *
 * Lo registra el plugin AntiScraping (no forma parte del núcleo). Consume tres eventos:
 * - "bot.environment" (AutomationMonitor): webdriver, headless, artefactos de frameworks
 *   de automatización (critical/high) e inconsistencias del entorno ("bot.env-*", de
 *   peso bajo: por sí solas no bastan para acusar a un navegador real);
 * - "bot.activity" (InteractionMonitor): eventos sintéticos, ausencia de interacción o,
 *   en sentido contrario, interacción humana confiable (señal de peso negativo);
 * - "network.request": ráfagas de solicitudes y barridos secuenciales de ids.
 *
 * Evita falsos positivos y ruido así:
 * - cada señal se reporta una sola vez por sesión (Reported);
 * - los transportes pasivos (imágenes, formularios, ...) no cuentan para el ritmo;
 * - la falta de interacción solo cuenta con la pestaña visible y sin scroll.
 *
 * Las señales alimentan además el veredicto de sesión (BotSession), aunque el hallazgo
 * no supere el umbral de reporte.
 */
export class BotDetector implements Detector {
  public readonly Name = "BotDetector";
  public readonly Handles = ["bot.environment", "bot.activity", "network.request"] as const;
  /** Señales ya emitidas en esta sesión (deduplicación). */
  private readonly Reported = new Set<RiskSignal>();
  private readonly Tracker: RequestPatternTracker;

  public constructor(private readonly Settings: ResolvedAntiScrapingConfig) {
    this.Tracker = new RequestPatternTracker(Settings.MaxRequestsPerMinute);
  }

  public Analyze(event: SecurityEvent): FindingCandidate | null {
    switch (event.Type) {
      case "bot.environment":
        return this.AnalyzeEnvironment(event.Data as BotEnvironmentData);
      case "bot.activity":
        return this.AnalyzeActivity(event.Data as BotActivityData);
      case "network.request":
        return this.AnalyzeRequest(event.Data as NetworkRequestData, event.Timestamp);
      default:
        return null;
    }
  }

  /** Filtra señales ya reportadas y marca las nuevas. */
  private Fresh(signals: RiskSignal[]): RiskSignal[] {
    const fresh = [...new Set(signals)].filter((signal) => !this.Reported.has(signal));
    for (const signal of fresh) {
      this.Reported.add(signal);
    }
    return fresh;
  }

  private AnalyzeEnvironment(data: BotEnvironmentData): FindingCandidate | null {
    const signals = this.Fresh(
      data.Signals.map(MapEnvironmentSignal).filter(
        (signal): signal is RiskSignal => signal !== null,
      ),
    );
    if (signals.length === 0) {
      return null;
    }
    // Basta una señal fuera de "bot.env-*" (webdriver, headless, artefacto) para hablar
    // de automatización; solo con inconsistencias se describe como entorno sospechoso.
    const automation = signals.some((signal) => !signal.startsWith("bot.env-"));
    return {
      Category: "bot",
      Title: automation ? "Browser automation detected" : "Inconsistent browser environment",
      Description: automation
        ? "The browser exposes traces of automation tools (webdriver, headless mode or automation frameworks)."
        : "The browser environment has inconsistencies typical of headless or spoofed browsers.",
      Signals: signals,
      Evidence: { Indicators: data.Signals, Phase: data.Phase },
    };
  }

  /**
   * Evalúa un resumen de interacción. Los contadores del monitor son acumulativos, así
   * que tras una interacción humana confiable la ausencia de interacción ya no se evalúa
   * en checkpoints posteriores; la señal negativa se emite una sola vez (deduplicada).
   */
  private AnalyzeActivity(data: BotActivityData): FindingCandidate | null {
    if (!this.Settings.Signals.Interaction) {
      return null;
    }
    // Pointer/Keyboard/Touch cuentan solo eventos isTrusted; los sintéticos van en Untrusted.
    const human = data.Pointer + data.Keyboard + data.Touch;
    const candidates: RiskSignal[] = [];
    if (data.Untrusted >= SyntheticEventThreshold) {
      candidates.push("bot.synthetic-events");
    }
    if (human > 0) {
      candidates.push("bot.human-interaction");
    } else if (
      // Solo en los checkpoints temporales del monitor y con la pestaña visible: una
      // pestaña en segundo plano sin interacción es normal. El scroll también descarta
      // la señal, porque leer haciendo solo scroll es comportamiento humano habitual.
      data.Reason === "checkpoint" &&
      data.ElapsedMs >= NoInteractionAfterMs &&
      data.Scroll === 0 &&
      data.Visible
    ) {
      candidates.push("bot.no-interaction");
    }

    const signals = this.Fresh(candidates);
    if (signals.length === 0) {
      return null;
    }
    const onlyHuman = signals.length === 1 && signals[0] === "bot.human-interaction";
    return {
      Category: "bot",
      Title: onlyHuman ? "Human interaction observed" : "Non-human interaction pattern",
      Description: onlyHuman
        ? "Trusted pointer, keyboard or touch input was observed in this session."
        : signals.includes("bot.synthetic-events")
          ? "Input events are being generated by scripts instead of a real user."
          : "The page has been visible without any pointer, keyboard, touch or scroll input.",
      Signals: signals,
      Evidence: { ...data },
    };
  }

  /**
   * Alimenta el RequestPatternTracker con solicitudes hechas por código. Se ignoran las
   * que no tienen origen (data:, blob:, ...) y los transportes pasivos.
   */
  private AnalyzeRequest(data: NetworkRequestData, timestamp: number): FindingCandidate | null {
    if (
      !this.Settings.Signals.RequestRate ||
      data.Origin === null ||
      PassiveTransports.has(data.Transport)
    ) {
      return null;
    }
    const pattern = this.Tracker.Record(data.Url, timestamp);
    const candidates: RiskSignal[] = [];
    if (pattern.Burst) {
      candidates.push("bot.request-burst");
    }
    if (pattern.SequentialRun >= this.Settings.SequentialThreshold) {
      candidates.push("bot.sequential-crawl");
    }
    const signals = this.Fresh(candidates);
    if (signals.length === 0) {
      return null;
    }
    return {
      Category: "bot",
      Title: "Scraping-like request pattern",
      Description: signals.includes("bot.sequential-crawl")
        ? `Sequential crawl detected: ${pattern.SequentialRun} consecutive ids requested on ${pattern.Template ?? "a URL pattern"}.`
        : `Request burst detected: ${pattern.RequestsLastMinute} requests in the last minute.`,
      Signals: signals,
      Evidence: {
        RequestsLastMinute: pattern.RequestsLastMinute,
        SequentialRun: pattern.SequentialRun,
        Pattern: pattern.Template,
        Transport: data.Transport,
      },
    };
  }
}
