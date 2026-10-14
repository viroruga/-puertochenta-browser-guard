/**
 * Tarea periódica de bajo impacto.
 *
 * - Usa referencias a setTimeout/clearTimeout capturadas al construirse, de modo que
 *   un reemplazo posterior de esas funciones no afecte (ni sea afectado por) la verificación.
 * - Cuando existe requestIdleCallback, ejecuta el trabajo en un período ocioso
 *   del navegador para no competir con la aplicación.
 * - Encadena timeouts en lugar de setInterval: nunca se acumulan ejecuciones.
 * - Un error de `Work` se descarta y la tarea continúa.
 *
 * La usan los monitores que verifican por sondeo (RuntimeMonitor, PrototypeMonitor,
 * AutomationMonitor).
 */
export class PeriodicTask {
  private readonly SetTimer = globalThis.setTimeout.bind(globalThis);
  private readonly ClearTimer = globalThis.clearTimeout.bind(globalThis);
  private readonly RequestIdle =
    typeof globalThis.requestIdleCallback === "function"
      ? globalThis.requestIdleCallback.bind(globalThis)
      : null;
  private readonly CancelIdle =
    typeof globalThis.cancelIdleCallback === "function"
      ? globalThis.cancelIdleCallback.bind(globalThis)
      : null;

  /** Timeout pendiente hasta la próxima ejecución, o null. */
  private TimerId: ReturnType<typeof setTimeout> | null = null;
  /** Callback ocioso pendiente (ya venció el intervalo y se espera un período libre). */
  private IdleId: number | null = null;
  private Running = false;

  /**
   * @param Work trabajo a ejecutar en cada ciclo; puede llamar a Stop().
   * @param IntervalMs espera entre el fin de una ejecución y la siguiente, en ms. Con
   *   requestIdleCallback, también es la demora máxima adicional hasta un período ocioso.
   */
  public constructor(
    private readonly Work: () => void,
    private readonly IntervalMs: number,
  ) {}

  /** Programa la primera ejecución tras IntervalMs (no ejecuta de inmediato). Idempotente. */
  public Start(): void {
    if (this.Running) {
      return;
    }
    this.Running = true;
    this.Schedule();
  }

  /** Cancela la ejecución pendiente. Se puede volver a llamar a Start(). */
  public Stop(): void {
    this.Running = false;
    if (this.TimerId !== null) {
      this.ClearTimer(this.TimerId);
      this.TimerId = null;
    }
    if (this.IdleId !== null && this.CancelIdle) {
      this.CancelIdle(this.IdleId);
    }
    this.IdleId = null;
  }

  public IsRunning(): boolean {
    return this.Running;
  }

  private Schedule(): void {
    this.TimerId = this.SetTimer(() => {
      this.TimerId = null;
      if (!this.Running) {
        return;
      }
      if (this.RequestIdle) {
        // `timeout` garantiza que el trabajo se ejecute aunque el navegador nunca quede
        // ocioso (p. ej. una página con animaciones continuas).
        this.IdleId = this.RequestIdle(
          () => {
            this.IdleId = null;
            this.Execute();
          },
          { timeout: this.IntervalMs },
        );
      } else {
        this.Execute();
      }
    }, this.IntervalMs);
  }

  private Execute(): void {
    if (!this.Running) {
      return;
    }
    try {
      this.Work();
    } catch {
      // Un error interno nunca debe propagarse a la aplicación host.
    }
    // Work() puede haber detenido la tarea.
    if (this.IsRunning()) {
      this.Schedule();
    }
  }
}
