import type { Monitor, MonitorStatus } from "../Types/Monitor";

/**
 * Registro de monitores. Inicia y detiene todos de forma aislada:
 * el fallo de un monitor no impide que los demás funcionen.
 */
export class MonitorRegistry {
  private readonly Monitors: Monitor[] = [];

  public constructor(private readonly OnError: (error: unknown, monitor: Monitor) => void) {}

  public Register(monitor: Monitor): void {
    if (this.Monitors.some((existing) => existing.Name === monitor.Name)) {
      throw new Error(`Monitor "${monitor.Name}" is already registered`);
    }
    this.Monitors.push(monitor);
  }

  public Get(name: string): Monitor | undefined {
    return this.Monitors.find((monitor) => monitor.Name === name);
  }

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

  public GetStatus(): MonitorStatus[] {
    return this.Monitors.map((monitor) => ({ Name: monitor.Name, Running: monitor.IsRunning() }));
  }

  public get Count(): number {
    return this.Monitors.length;
  }
}
