import type { Monitor, MonitorStatus } from "../Types/Monitor";

/**
 * Registro de monitores. Inicia y detiene todos de forma aislada:
 * el fallo de un monitor no impide que los demás funcionen.
 *
 * BrowserGuard registra aquí los monitores del núcleo (Components.CreateMonitors) y los
 * de los plugins, en orden de inicio; GetStatus() alimenta GetStatus().Monitors.
 */
export class MonitorRegistry {
  private readonly Monitors: Monitor[] = [];

  /** @param OnError Se invoca cuando Start() o Stop() de un monitor lanza. */
  public constructor(private readonly OnError: (error: unknown, monitor: Monitor) => void) {}

  /**
   * Agrega un monitor al final del orden de inicio.
   * Lanza si ya hay uno con el mismo nombre: el nombre identifica al monitor en el estado.
   */
  public Register(monitor: Monitor): void {
    if (this.Monitors.some((existing) => existing.Name === monitor.Name)) {
      throw new Error(`Monitor "${monitor.Name}" is already registered`);
    }
    this.Monitors.push(monitor);
  }

  /** Monitor registrado con ese nombre, si existe. */
  public Get(name: string): Monitor | undefined {
    return this.Monitors.find((monitor) => monitor.Name === name);
  }

  /** Inicia, en orden de registro, los monitores que aún no están en ejecución. */
  public StartAll(): void {
    for (const monitor of this.Monitors) {
      if (monitor.IsRunning()) {
        continue;
      }
      try {
        monitor.Start();
      } catch (error) {
        this.OnError(error, monitor);
      }
    }
  }

  /**
   * Detiene los monitores en orden inverso al de inicio, para que las
   * interceptaciones encadenadas se deshagan correctamente.
   */
  public StopAll(): void {
    for (const monitor of [...this.Monitors].reverse()) {
      try {
        monitor.Stop();
      } catch (error) {
        this.OnError(error, monitor);
      }
    }
  }

  /** Nombre y estado de ejecución de cada monitor, en orden de registro. */
  public GetStatus(): MonitorStatus[] {
    return this.Monitors.map((monitor) => ({ Name: monitor.Name, Running: monitor.IsRunning() }));
  }

  /** Cantidad de monitores registrados. */
  public get Count(): number {
    return this.Monitors.length;
  }
}
