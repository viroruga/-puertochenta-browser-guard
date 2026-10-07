import type { RuntimeModificationData } from "../Types/SecurityEvent";
import { AnalyzeFunction } from "../Utils/NativeFunctionUtils";
import { PeriodicTask } from "../Utils/PeriodicTask";
import { BaseMonitor } from "./BaseMonitor";

type RuntimeWindow = Window & typeof globalThis;

interface RuntimeTarget {
  Name: string;
  /** Objeto que contiene la función (window, un prototipo, ...). */
  Owner: (window: RuntimeWindow) => object | undefined;
  Key: string;
  IsConstructor?: boolean;
}

const OnWindow = (window: RuntimeWindow): object => window;
const OnXhrPrototype = (window: RuntimeWindow): object | undefined =>
  (window.XMLHttpRequest as typeof XMLHttpRequest | undefined)?.prototype;
const OnElementPrototype = (window: RuntimeWindow): object => window.Element.prototype;
const OnFunctionPrototype = (window: RuntimeWindow): object => window.Function.prototype;

/**
 * Funciones críticas cuyo reemplazo suele indicar instrumentación maliciosa
 * (exfiltración, ocultamiento o ejecución de código).
 */
export const RuntimeTargets: readonly RuntimeTarget[] = [
  { Name: "window.fetch", Owner: OnWindow, Key: "fetch" },
  { Name: "XMLHttpRequest.prototype.open", Owner: OnXhrPrototype, Key: "open" },
  { Name: "XMLHttpRequest.prototype.send", Owner: OnXhrPrototype, Key: "send" },
  { Name: "WebSocket", Owner: OnWindow, Key: "WebSocket", IsConstructor: true },
  { Name: "setTimeout", Owner: OnWindow, Key: "setTimeout" },
  { Name: "setInterval", Owner: OnWindow, Key: "setInterval" },
  { Name: "eval", Owner: OnWindow, Key: "eval" },
  { Name: "Function", Owner: OnWindow, Key: "Function", IsConstructor: true },
  { Name: "Element.prototype.appendChild", Owner: OnElementPrototype, Key: "appendChild" },
  { Name: "Element.prototype.setAttribute", Owner: OnElementPrototype, Key: "setAttribute" },
  { Name: "Function.prototype.toString", Owner: OnFunctionPrototype, Key: "toString" },
];

/**
 * Verifica periódicamente la integridad de funciones críticas del runtime.
 *
 * - Al iniciar toma un baseline de referencias; si alguna ya parece no nativa,
 *   emite un evento de fase "baseline" (modificación previa a BrowserGuard).
 * - En cada verificación compara por identidad (costo O(n), n ≈ 11) y, solo si
 *   cambió, analiza la nueva función con NativeFunctionUtils.
 * - Ignora los interceptores instalados por la propia librería.
 */
export class RuntimeMonitor extends BaseMonitor {
  public readonly Name = "RuntimeMonitor";
  /** Referencias al iniciar: volver a ellas es una restauración, no un cambio sospechoso. */
  private Initial = new Map<string, unknown>();
  /** Última referencia observada. */
  private Baseline = new Map<string, unknown>();
  private Task: PeriodicTask | null = null;

  protected OnStart(): boolean {
    for (const target of RuntimeTargets) {
      const value = this.Read(target);
      this.Initial.set(target.Name, value);
      this.Baseline.set(target.Name, value);
      if (typeof value === "function" && !this.Context.IsOwnFunction(value)) {
        const analysis = this.Analyze(target, value);
        if (!analysis.LooksNative) {
          this.EmitChange({ Target: target.Name, Phase: "baseline", Analysis: analysis });
        }
      }
    }
    this.Task = new PeriodicTask(() => {
      this.CheckNow();
    }, this.Context.Config.Integrity.IntervalMs);
    this.Task.Start();
    return true;
  }

  protected OnStop(): void {
    this.Task?.Stop();
    this.Task = null;
    this.Initial = new Map();
    this.Baseline = new Map();
  }

  /**
   * Compara las referencias actuales contra el baseline. Cada cambio se reporta una vez.
   */
  public CheckNow(): void {
    if (!this.IsRunning()) {
      return;
    }
    for (const target of RuntimeTargets) {
      const current = this.Read(target);
      const previous = this.Baseline.get(target.Name);
      if (current === previous || this.Context.IsOwnFunction(current)) {
        continue;
      }
      this.Baseline.set(target.Name, current);
      if (current === this.Initial.get(target.Name)) {
        continue;
      }

      if (typeof current !== "function") {
        if (typeof previous === "function") {
          this.EmitChange({ Target: target.Name, Phase: "removed" });
        }
        continue;
      }
      this.EmitChange({
        Target: target.Name,
        Phase: "change",
        Analysis: this.Analyze(target, current),
      });
    }
  }

  private Read(target: RuntimeTarget): unknown {
    try {
      const owner = target.Owner(this.Context.Window);
      return owner === undefined ? undefined : Reflect.get(owner, target.Key);
    } catch {
      return undefined;
    }
  }

  private Analyze(target: RuntimeTarget, value: unknown): ReturnType<typeof AnalyzeFunction> {
    return AnalyzeFunction(value, {
      ExpectedName: target.Key,
      IsConstructor: target.IsConstructor === true,
    });
  }

  private EmitChange(data: RuntimeModificationData): void {
    this.Context.Emit("runtime.modified", this.Name, data);
  }
}
