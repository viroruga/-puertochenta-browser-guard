import { ResolveConfig } from "./Config/ResolveConfig";
import { CreateDetectors, CreateMonitors, CreateReporters } from "./Core/Components";
import { EventBus } from "./Core/EventBus";
import { FindingHistory } from "./Core/FindingHistory";
import { GuardStore } from "./Core/GuardStore";
import { GuardContext } from "./Core/GuardContext";
import { MonitorRegistry } from "./Core/MonitorRegistry";
import { OriginLearner } from "./Core/OriginLearner";
import { PluginManager } from "./Core/PluginManager";
import { RiskEngine } from "./Core/RiskEngine";
import { ShowConsoleNotice } from "./Reporters/ConsoleNotice";
import type { Reporter } from "./Reporters/Reporter";
import type { BotAssessment } from "./Types/Bot";
import type { BrowserGuardConfig, ResolvedConfig } from "./Types/BrowserGuardConfig";
import type { Detector } from "./Types/Detector";
import type {
  FindingEventName,
  GuardEventHandler,
  GuardEventName,
  GuardSnapshot,
  GuardStatus,
  PublicEventMap,
} from "./Types/GuardStatus";
import type {
  InternalEventMap,
  SecurityEvent,
  SecurityEventType,
  TypedSecurityEvent,
} from "./Types/SecurityEvent";
import type { GuardReport, SecurityFinding } from "./Types/SecurityFinding";
import type { Severity } from "./Types/Severity";
import { RingBuffer } from "./Utils/RingBuffer";

/**
 * Clave global de la instancia activa. Se usa Symbol.for para que la idempotencia
 * se mantenga aunque el módulo se reevalúe (HMR) o existan dos copias del bundle.
 * Es la única referencia global que crea la librería.
 */
const ActiveInstanceKey = Symbol.for("puertochenta.browser-guard.active-instance");

type GuardGlobal = typeof globalThis & { [ActiveInstanceKey]?: BrowserGuard };

const SeverityEvents: Record<Severity, FindingEventName> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

function IsBrowserEnvironment(): boolean {
  return typeof window !== "undefined" && typeof document !== "undefined";
}

function GetActiveInstance(): BrowserGuard | null {
  return (globalThis as GuardGlobal)[ActiveInstanceKey] ?? null;
}

function SetActiveInstance(instance: BrowserGuard | null): void {
  const global = globalThis as GuardGlobal;
  if (instance) {
    global[ActiveInstanceKey] = instance;
  } else {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete -- Clave simbólica fija.
    delete global[ActiveInstanceKey];
  }
}

/**
 * Re-lanza de forma asíncrona un error de un manejador de la aplicación,
 * igual que hace el DOM con los listeners: no interrumpe a BrowserGuard,
 * pero el error sigue siendo visible para el desarrollador.
 */
function ReportHandlerError(error: unknown): void {
  if (typeof globalThis.reportError === "function") {
    globalThis.reportError(error);
    return;
  }
  queueMicrotask(() => {
    throw error;
  });
}

/**
 * Punto de entrada de la librería.
 *
 * Flujo: Monitors → GuardContext (cola) → EventBus interno → Detectors → RiskEngine
 *        → SecurityFinding → historial + eventos públicos + Reporters.
 *
 * Start() es idempotente: mientras exista una instancia en ejecución, retorna esa
 * misma instancia e ignora la nueva configuración.
 */
export class BrowserGuard {
  private readonly Config: ResolvedConfig;
  private readonly Supported: boolean;
  private readonly StartedAt = Date.now();
  private StoppedAt: number | null = null;
  private Running = false;
  private HandlerErrors = 0;

  private readonly PublicBus = new EventBus<PublicEventMap>((error) => {
    ReportHandlerError(error);
  });
  private readonly InternalBus = new EventBus<InternalEventMap>(() => {
    this.HandlerErrors++;
  });
  private readonly Registry = new MonitorRegistry(() => {
    this.HandlerErrors++;
  });
  private readonly History: FindingHistory;
  private readonly Timeline: RingBuffer<SecurityEvent> | null;
  private readonly Engine: RiskEngine;
  private Reporters: Reporter[] = [];
  private readonly CustomReporters: Reporter[];
  private readonly Plugins: PluginManager;
  private readonly Store: GuardStore;
  private Context: GuardContext | null = null;
  /** Solo con Learning.Enabled. Se conserva después de Stop() para consultar lo aprendido. */
  private Learner: OriginLearner | null = null;
  private readonly Unsubscribers: (() => void)[] = [];

  private constructor(config: BrowserGuardConfig) {
    this.Config = ResolveConfig(config);
    // Los reporters propios no forman parte de ResolvedConfig (que debe ser clonable).
    this.CustomReporters = (Array.isArray(config.Reporters) ? config.Reporters : []).filter(
      (reporter) => typeof (reporter as Partial<Reporter> | null)?.Report === "function",
    );
    // Los plugins tampoco: contienen funciones y viven fuera de la configuración clonable.
    this.Plugins = new PluginManager(config.Plugins, () => {
      this.HandlerErrors++;
    });
    this.Supported = IsBrowserEnvironment();
    this.History = new FindingHistory(this.Config.History.MaxFindings);
    this.Timeline = this.Config.Forensic.Enabled
      ? new RingBuffer<SecurityEvent>(this.Config.Forensic.MaxEvents)
      : null;
    this.Engine = new RiskEngine(this.Config.Risk.Weights, this.Config.Risk.MinSeverity);
    this.Store = new GuardStore(
      { Running: false, Bot: null, LastFinding: null, Statistics: this.History.GetStatistics() },
      ReportHandlerError,
    );
  }

  // ───────────────────────────── API estática ─────────────────────────────

  /**
   * Inicia BrowserGuard y retorna la instancia activa.
   * Si ya hay una instancia en ejecución, la retorna sin crear interceptores nuevos.
   * En entornos sin navegador (SSR) retorna una instancia inerte.
   */
  public static Start(config: BrowserGuardConfig = {}): BrowserGuard {
    const existing = GetActiveInstance();
    if (existing?.IsRunning()) {
      return existing;
    }
    const guard = new BrowserGuard(config);
    guard.Activate();
    if (guard.IsRunning()) {
      SetActiveInstance(guard);
    }
    return guard;
  }

  /** Detiene la instancia activa, si existe. */
  public static Stop(): void {
    GetActiveInstance()?.Stop();
  }

  /** Suscribe un manejador en la instancia activa. Sin instancia activa no hace nada. */
  public static On<K extends GuardEventName>(event: K, handler: GuardEventHandler<K>): () => void {
    const active = GetActiveInstance();
    return active ? active.On(event, handler) : () => undefined;
  }

  public static Off<K extends GuardEventName>(event: K, handler: GuardEventHandler<K>): void {
    GetActiveInstance()?.Off(event, handler);
  }

  /** Veredicto del plugin AntiScraping de la instancia activa, o null. */
  public static GetBotAssessment(): BotAssessment | null {
    return GetActiveInstance()?.GetBotAssessment() ?? null;
  }

  public static GetReport(): GuardReport | null {
    return GetActiveInstance()?.GetReport() ?? null;
  }

  public static GetStatus(): GuardStatus | null {
    return GetActiveInstance()?.GetStatus() ?? null;
  }

  public static GetTimeline(): SecurityEvent[] {
    return GetActiveInstance()?.GetTimeline() ?? [];
  }

  /** Configuración propuesta por el modo aprendizaje de la instancia activa, o null. */
  public static GetLearnedConfig(): BrowserGuardConfig | null {
    return GetActiveInstance()?.GetLearnedConfig() ?? null;
  }

  /** Retorna la instancia en ejecución, o null. */
  public static GetInstance(): BrowserGuard | null {
    return GetActiveInstance();
  }

  // ──────────────────────────── API de instancia ───────────────────────────

  public On<K extends GuardEventName>(event: K, handler: GuardEventHandler<K>): () => void {
    return this.PublicBus.On(event, handler);
  }

  public Once<K extends GuardEventName>(event: K, handler: GuardEventHandler<K>): () => void {
    return this.PublicBus.Once(event, handler);
  }

  public Off<K extends GuardEventName>(event: K, handler: GuardEventHandler<K>): void {
    this.PublicBus.Off(event, handler);
  }

  /**
   * Veredicto del plugin AntiScraping, o null si no está activo.
   * Útil para que la aplicación decida no renderizar datos sensibles.
   */
  public GetBotAssessment(): BotAssessment | null {
    return this.Plugins.GetBotAssessment();
  }

  public IsRunning(): boolean {
    return this.Running;
  }

  /**
   * Suscribe un listener a los cambios del snapshot. Retorna la función para desuscribirlo.
   * Compatible con useSyncExternalStore de React (función estable, enlazada).
   */
  public readonly Subscribe = (listener: () => void): (() => void) =>
    this.Store.Subscribe(listener);

  /** Snapshot inmutable actual (misma referencia mientras no cambie). */
  public readonly GetSnapshot = (): GuardSnapshot => this.Store.Get();

  /**
   * Detiene todos los monitores, restaura las funciones interceptadas y libera
   * listeners y timers. El historial sigue disponible mediante GetReport().
   */
  public Stop(): void {
    if (!this.Running) {
      return;
    }
    this.Running = false;
    this.StoppedAt = Date.now();

    this.Registry.StopAll();
    // Se procesan los eventos capturados antes de detener, y luego se descarta el contexto.
    this.Context?.Flush();
    this.Plugins.Dispose();
    this.Context?.Dispose();

    for (const unsubscribe of this.Unsubscribers.splice(0)) {
      unsubscribe();
    }
    this.InternalBus.Clear();
    for (const reporter of this.Reporters) {
      try {
        reporter.Dispose?.();
      } catch {
        this.HandlerErrors++;
      }
    }
    this.Reporters = [];
    this.PublicBus.Clear();
    this.Store.Update({ Running: false });

    if (GetActiveInstance() === this) {
      SetActiveInstance(null);
    }
  }

  public GetReport(): GuardReport {
    return {
      StartedAt: this.StartedAt,
      Findings: this.History.GetFindings(),
      Statistics: this.History.GetStatistics(),
    };
  }

  public GetStatus(): GuardStatus {
    return {
      Supported: this.Supported,
      Running: this.Running,
      Preset: this.Config.Preset,
      StartedAt: this.StartedAt,
      StoppedAt: this.StoppedAt,
      Monitors: this.Registry.GetStatus(),
      FindingsCount: this.History.Size,
      TimelineSize: this.Timeline?.Size ?? 0,
      DroppedEvents: this.Context?.DroppedEvents ?? 0,
      InternalErrors: this.HandlerErrors + (this.Context?.InternalErrors ?? 0),
      Plugins: this.Plugins.GetStatus(),
      Remote: this.Plugins.GetRemoteStats(),
      Bot: this.Plugins.GetBotAssessment(),
      SessionId: this.Context?.SessionId ?? null,
    };
  }

  /**
   * Línea de tiempo de eventos internos recientes (solo en modo forense).
   */
  public GetTimeline(): SecurityEvent[] {
    return this.Timeline?.ToArray() ?? [];
  }

  /** Copia de la configuración efectiva. */
  public GetConfig(): ResolvedConfig {
    return structuredClone(this.Config);
  }

  /**
   * Orígenes de terceros observados en modo aprendizaje que aún no están permitidos,
   * listos para agregar a la configuración. null si Learning no está habilitado.
   * Revísalos antes de adoptarlos: lo que estuvo presente durante el aprendizaje
   * (incluido un script malicioso) también aparece.
   */
  public GetLearnedConfig(): BrowserGuardConfig | null {
    return this.Learner?.GetLearnedConfig() ?? null;
  }

  // ─────────────────────────────── Internos ────────────────────────────────

  private Activate(): void {
    if (!this.Supported) {
      return;
    }
    const context = new GuardContext(this.Config, window, (event) => {
      this.DispatchEvent(event);
    });
    this.Context = context;
    if (this.Config.Learning.Enabled) {
      this.Learner = new OriginLearner(this.Config, () => context.GetPageOrigin());
    }

    // Los plugins se instalan antes de crear e iniciar los monitores: pueden capturar
    // referencias originales (fetch) y proveer el header de veredicto desde el inicio.
    this.Plugins.Setup(this.Config, context, this.Engine, (assessment) => {
      this.PublicBus.Emit("Bot", assessment);
      this.Store.Update({ Bot: assessment });
    });
    this.Reporters = [
      ...CreateReporters(this.Config),
      ...this.Plugins.Reporters,
      ...this.CustomReporters,
    ];
    for (const detector of [...CreateDetectors(this.Config, context), ...this.Plugins.Detectors]) {
      this.AttachDetector(detector);
    }
    for (const monitor of [...CreateMonitors(context), ...this.Plugins.Monitors]) {
      this.Registry.Register(monitor);
    }
    this.Running = true;
    this.Registry.StartAll();
    this.Store.Update({ Running: true, Bot: this.Plugins.GetBotAssessment() });

    if (this.Config.Console === "notice") {
      context.Safely(() => {
        ShowConsoleNotice(this.Config.Notice);
      });
    }
  }

  private AttachDetector(detector: Detector): void {
    for (const type of detector.Handles) {
      this.Unsubscribers.push(
        this.InternalBus.On(type, (event) => {
          this.RunDetector(detector, event);
        }),
      );
    }
  }

  private DispatchEvent<K extends SecurityEventType>(event: TypedSecurityEvent<K>): void {
    this.Timeline?.Push(event);
    if (this.Learner) {
      this.Learn(event);
    }
    this.InternalBus.Emit(event.Type, event as InternalEventMap[K]);
  }

  private Learn(event: SecurityEvent): void {
    const learner = this.Learner;
    if (event.Type === "network.request") {
      learner?.ObserveRequest((event as InternalEventMap["network.request"]).Data);
    } else if (event.Type === "dom.element-inserted") {
      learner?.ObserveElement((event as InternalEventMap["dom.element-inserted"]).Data);
    }
  }

  private RunDetector(detector: Detector, event: SecurityEvent): void {
    const candidate = detector.Analyze(event);
    if (!candidate) {
      return;
    }
    const finding = this.Engine.Evaluate(candidate, event);
    if (finding) {
      this.Publish(Object.freeze(finding));
    }
    this.Plugins.NotifyCandidate(candidate);
  }

  private Publish(finding: SecurityFinding): void {
    this.History.Add(finding);
    this.Store.Update({ LastFinding: finding, Statistics: this.History.GetStatistics() });

    this.PublicBus.Emit("Finding", finding);
    if (finding.Severity !== "info") {
      this.PublicBus.Emit("Threat", finding);
    }
    this.PublicBus.Emit(SeverityEvents[finding.Severity], finding);

    for (const reporter of this.Reporters) {
      try {
        reporter.Report(finding);
      } catch {
        this.HandlerErrors++;
      }
    }
  }
}
