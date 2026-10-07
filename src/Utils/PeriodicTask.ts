/**
 * Tarea periódica de bajo impacto.
 *
 * - Usa referencias a setTimeout/clearTimeout capturadas al construirse, de modo que
 *   un reemplazo posterior de esas funciones no afecte (ni sea afectado por) la verificación.
 * - Cuando existe requestIdleCallback, ejecuta el trabajo en un período ocioso
 *   del navegador para no competir con la aplicación.
 * - Encadena timeouts en lugar de setInterval: nunca se acumulan ejecuciones.
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

  private TimerId: ReturnType<typeof setTimeout> | null = null;
  private IdleId: number | null = null;
  private Running = false;

  public constructor(
    private readonly Work: () => void,
    private readonly IntervalMs: number,
  ) {}

  public Start(): void {
    if (this.Running) {
      return;
    }
    this.Running = true;
    this.Schedule();
  }

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
