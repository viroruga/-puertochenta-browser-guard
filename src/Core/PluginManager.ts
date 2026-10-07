import type { Reporter } from "../Reporters/Reporter";
import type { BotAssessment } from "../Types/Bot";
import type { ResolvedConfig } from "../Types/BrowserGuardConfig";
import type { Detector, FindingCandidate } from "../Types/Detector";
import type { Monitor } from "../Types/Monitor";
import type { GuardPlugin, PluginHost, PluginStatus } from "../Types/Plugin";
import type { RemoteStats } from "../Types/Remote";
import type { GuardContext } from "./GuardContext";
import type { RiskEngine } from "./RiskEngine";

/**
 * Filtra entradas inválidas de la configuración (los plugins vienen del usuario).
 */
function IsPlugin(value: unknown): value is GuardPlugin {
  const plugin = value as Partial<GuardPlugin> | null;
  return typeof plugin?.Name === "string" && typeof plugin.Setup === "function";
}

/**
 * Instala los plugins y guarda lo que aportan: monitores, detectores, reporters,
 * listeners y proveedores de estado.
 *
 * Aislamiento: un plugin que falla en Setup() o en un listener no afecta a los demás
 * ni a la aplicación; queda inactivo y el error se contabiliza.
 */
export class PluginManager {
  public readonly Monitors: Monitor[] = [];
  public readonly Detectors: Detector[] = [];
  public readonly Reporters: Reporter[] = [];

  private readonly Plugins: GuardPlugin[];
  private readonly CandidateListeners: ((candidate: FindingCandidate) => void)[] = [];
  private readonly DisposeListeners: (() => void)[] = [];
  private Statuses: PluginStatus[] = [];
  private BotProvider: (() => BotAssessment) | null = null;
  private RemoteProvider: (() => RemoteStats) | null = null;

  public constructor(
    plugins: unknown,
    private readonly OnError: (error: unknown) => void,
  ) {
    this.Plugins = Array.isArray(plugins) ? plugins.filter(IsPlugin) : [];
  }

  /**
   * Ejecuta Setup() de cada plugin. Un nombre repetido se ignora (gana el primero).
   */
  public Setup(
    config: ResolvedConfig,
    context: GuardContext,
    engine: RiskEngine,
    emitBot: (assessment: BotAssessment) => void,
  ): void {
    const host: PluginHost = {
      Config: config,
      Context: context,
      Engine: engine,
      AddMonitor: (monitor) => this.Monitors.push(monitor),
      AddDetector: (detector) => this.Detectors.push(detector),
      AddReporter: (reporter) => this.Reporters.push(reporter),
      OnCandidate: (listener) => this.CandidateListeners.push(listener),
      OnDispose: (listener) => this.DisposeListeners.push(listener),
      EmitBot: emitBot,
      ProvideBotAssessment: (provider) => {
        this.BotProvider = provider;
      },
      ProvideRemoteStats: (provider) => {
        this.RemoteProvider = provider;
      },
    };

    const seen = new Set<string>();
    this.Statuses = this.Plugins.map((plugin) => {
      if (seen.has(plugin.Name)) {
        return { Name: plugin.Name, Active: false };
      }
      seen.add(plugin.Name);
      try {
        return { Name: plugin.Name, Active: plugin.Setup(host) };
      } catch (error) {
        this.OnError(error);
        return { Name: plugin.Name, Active: false };
      }
    });
  }

  public NotifyCandidate(candidate: FindingCandidate): void {
    for (const listener of this.CandidateListeners) {
      try {
        listener(candidate);
      } catch (error) {
        this.OnError(error);
      }
    }
  }

  public Dispose(): void {
    for (const listener of this.DisposeListeners.splice(0)) {
      try {
        listener();
      } catch (error) {
        this.OnError(error);
      }
    }
  }

  public GetBotAssessment(): BotAssessment | null {
    return this.BotProvider?.() ?? null;
  }

  public GetRemoteStats(): RemoteStats | null {
    return this.RemoteProvider?.() ?? null;
  }

  public GetStatus(): PluginStatus[] {
    return this.Statuses.map((status) => ({ ...status }));
  }
}
