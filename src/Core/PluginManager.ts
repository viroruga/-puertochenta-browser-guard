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
 * Es la implementación de PluginHost: BrowserGuard lo crea con config.Plugins, ejecuta
 * Setup() antes de crear los monitores y luego toma Monitors/Detectors/Reporters para
 * conectarlos al pipeline junto a los del núcleo. Los plugins oficiales son
 * AntiScraping y RemoteReporting (rutas separadas del paquete).
 *
 * Aislamiento: un plugin que falla en Setup() o en un listener no afecta a los demás
 * ni a la aplicación; queda inactivo y el error se contabiliza.
 */
export class PluginManager {
  /** Monitores aportados con AddMonitor; BrowserGuard los registra después de los del núcleo. */
  public readonly Monitors: Monitor[] = [];
  public readonly Detectors: Detector[] = [];
  public readonly Reporters: Reporter[] = [];

  private readonly Plugins: GuardPlugin[];
  private readonly CandidateListeners: ((candidate: FindingCandidate) => void)[] = [];
  private readonly DisposeListeners: (() => void)[] = [];
  private Statuses: PluginStatus[] = [];
  /** Proveedor del veredicto de bot (AntiScraping); el último registrado gana. */
  private BotProvider: (() => BotAssessment) | null = null;
  /** Proveedor de contadores de envío remoto (RemoteReporting); el último registrado gana. */
  private RemoteProvider: (() => RemoteStats) | null = null;

  /**
   * @param plugins Valor de config.Plugins tal como lo pasó el usuario (sin validar).
   * @param OnError Contabiliza los errores de los plugins sin propagarlos.
   */
  public constructor(
    plugins: unknown,
    private readonly OnError: (error: unknown) => void,
  ) {
    this.Plugins = Array.isArray(plugins) ? plugins.filter(IsPlugin) : [];
  }

  /**
   * Ejecuta Setup() de cada plugin. Un nombre repetido se ignora (gana el primero).
   * Debe llamarse una sola vez: lo aportado se acumula en las listas públicas.
   *
   * @param emitBot Publica el evento "Bot" y actualiza el snapshot (lo provee BrowserGuard).
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

    // Nota: lo que un plugin agregó antes de lanzar en Setup() (monitores, listeners...)
    // no se revierte; solo queda marcado como inactivo.
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

  /**
   * Entrega a los plugins cada candidato de un detector, haya generado o no un hallazgo
   * (AntiScraping necesita las señales de bot aunque no alcancen Risk.MinSeverity).
   */
  public NotifyCandidate(candidate: FindingCandidate): void {
    for (const listener of this.CandidateListeners) {
      try {
        listener(candidate);
      } catch (error) {
        this.OnError(error);
      }
    }
  }

  /** Ejecuta los OnDispose de los plugins (una sola vez: la lista se vacía). */
  public Dispose(): void {
    for (const listener of this.DisposeListeners.splice(0)) {
      try {
        listener();
      } catch (error) {
        this.OnError(error);
      }
    }
  }

  /** Veredicto del proveedor de bot, o null si ningún plugin lo registró. */
  public GetBotAssessment(): BotAssessment | null {
    return this.BotProvider?.() ?? null;
  }

  /** Contadores de envío remoto, o null si ningún plugin los registró. */
  public GetRemoteStats(): RemoteStats | null {
    return this.RemoteProvider?.() ?? null;
  }

  /** Estado de cada plugin válido (copia), en el orden de la configuración. */
  public GetStatus(): PluginStatus[] {
    return this.Statuses.map((status) => ({ ...status }));
  }
}
