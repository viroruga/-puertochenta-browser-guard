import type { ResolvedAntiScrapingConfig } from "../Types/BrowserGuardConfig";
import { DetectAutomationSignals, DetectEnvironmentSignals } from "../Utils/AutomationSignals";
import { PeriodicTask } from "../Utils/PeriodicTask";
import type { GuardContext } from "../Core/GuardContext";
import { BaseMonitor } from "./BaseMonitor";

/**
 * Observa señales de automatización (webdriver, headless, artefactos de Puppeteer/
 * Playwright, ...) y de entorno inconsistente. Lo registra AntiScrapingPlugin.
 *
 * Emite `bot.environment`, que consume BotDetector.
 *
 * - Al iniciar ejecuta todas las comprobaciones habilitadas (las de entorno, una sola vez:
 *   describen el navegador y no cambian durante la sesión).
 * - Luego revisa periódicamente solo las de automatización, porque algunas
 *   herramientas inyectan sus globales después de cargar la página.
 * - Cada señal se emite una única vez por sesión.
 *
 * Privacidad: solo se emiten nombres de señal, nunca los valores leídos (user agent,
 * renderer WebGL, idiomas...), para no construir una huella identificable del usuario.
 */
export class AutomationMonitor extends BaseMonitor {
  public readonly Name = "AutomationMonitor";
  /** Señales ya emitidas: evita repetir el mismo evento en cada revisión periódica. */
  private Seen = new Set<string>();
  private Task: PeriodicTask | null = null;

  /**
   * @param Settings Configuración anti-scraping resuelta; decide qué grupos de señales se
   * comprueban.
   */
  public constructor(
    context: GuardContext,
    private readonly Settings: ResolvedAntiScrapingConfig,
  ) {
    super(context);
  }

  protected OnStart(): boolean {
    const window = this.Context.Window;
    const signals = [
      ...(this.Settings.Signals.Automation ? DetectAutomationSignals(window) : []),
      ...(this.Settings.Signals.Environment ? DetectEnvironmentSignals(window) : []),
    ];
    this.EmitNew(signals, "start");

    if (this.Settings.Signals.Automation) {
      // Reutiliza el intervalo de integridad: PeriodicTask corre en tiempo ocioso y no
      // compite con la aplicación.
      this.Task = new PeriodicTask(() => {
        this.CheckNow();
      }, this.Context.Config.Integrity.IntervalMs);
      this.Task.Start();
    }
    return true;
  }

  protected OnStop(): void {
    this.Task?.Stop();
    this.Task = null;
    this.Seen = new Set();
  }

  /** Revisa nuevamente las señales de automatización (sin efecto si está detenido). */
  public CheckNow(): void {
    if (this.IsRunning()) {
      this.EmitNew(DetectAutomationSignals(this.Context.Window), "recheck");
    }
  }

  /** Emite, en un único evento, solo las señales que no se habían reportado antes. */
  private EmitNew(signals: string[], phase: "start" | "recheck"): void {
    const fresh = signals.filter((signal) => !this.Seen.has(signal));
    if (fresh.length === 0) {
      return;
    }
    for (const signal of fresh) {
      this.Seen.add(signal);
    }
    this.Context.Emit("bot.environment", this.Name, { Phase: phase, Signals: fresh });
  }
}
