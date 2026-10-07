import type { ResolvedAntiScrapingConfig } from "../Types/BrowserGuardConfig";
import { DetectAutomationSignals, DetectEnvironmentSignals } from "../Utils/AutomationSignals";
import { PeriodicTask } from "../Utils/PeriodicTask";
import type { GuardContext } from "../Core/GuardContext";
import { BaseMonitor } from "./BaseMonitor";

/**
 * Observa señales de automatización y de entorno inconsistente.
 *
 * - Al iniciar ejecuta todas las comprobaciones habilitadas (las de entorno, una sola vez).
 * - Luego revisa periódicamente solo las de automatización, porque algunas
 *   herramientas inyectan sus globales después de cargar la página.
 * - Cada señal se emite una única vez por sesión.
 */
export class AutomationMonitor extends BaseMonitor {
  public readonly Name = "AutomationMonitor";
  private Seen = new Set<string>();
  private Task: PeriodicTask | null = null;

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

  /** Revisa nuevamente las señales de automatización. */
  public CheckNow(): void {
    if (this.IsRunning()) {
      this.EmitNew(DetectAutomationSignals(this.Context.Window), "recheck");
    }
  }

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
