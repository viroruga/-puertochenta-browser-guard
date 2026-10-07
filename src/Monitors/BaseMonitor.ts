import type { GuardContext } from "../Core/GuardContext";
import type { Monitor } from "../Types/Monitor";

/**
 * Base común de monitores: gestiona el estado de ejecución y garantiza que
 * Start/Stop sean idempotentes.
 */
export abstract class BaseMonitor implements Monitor {
  public abstract readonly Name: string;
  private Running = false;

  public constructor(protected readonly Context: GuardContext) {}

  public Start(): void {
    if (this.Running) {
      return;
    }
    let started = false;
    try {
      started = this.OnStart();
    } finally {
      // Si la API no está disponible o falló a mitad de camino, se deshace lo instalado.
      if (started) {
        this.Running = true;
      } else {
        this.OnStop();
      }
    }
  }

  public Stop(): void {
    if (!this.Running) {
      return;
    }
    this.Running = false;
    this.OnStop();
  }

  public IsRunning(): boolean {
    return this.Running;
  }

  /**
   * Instala la observación. Retorna false si la API observada no está disponible.
   */
  protected abstract OnStart(): boolean;

  /**
   * Retira toda observación y libera recursos. Debe tolerar llamadas sin OnStart previo.
   */
  protected abstract OnStop(): void;
}
