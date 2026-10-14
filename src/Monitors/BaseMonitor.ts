import type { GuardContext } from "../Core/GuardContext";
import type { Monitor } from "../Types/Monitor";

/**
 * Base común de todos los monitores: gestiona el estado de ejecución y garantiza que
 * Start/Stop sean idempotentes.
 *
 * Las subclases solo implementan OnStart/OnStop. Un monitor observa y emite eventos a
 * través de `Context.Emit`; nunca decide si algo es un ataque (eso es tarea de los
 * Detectors) ni bloquea a la aplicación.
 *
 * Si OnStart retorna false o lanza a mitad de camino, se invoca OnStop para deshacer lo
 * que se haya instalado: un monitor nunca queda "medio instalado". El error, si lo hay,
 * se propaga a quien llamó a Start (MonitorRegistry lo captura y lo contabiliza).
 */
export abstract class BaseMonitor implements Monitor {
  /** Nombre del monitor; se usa como `Source` de los eventos y en el estado público. */
  public abstract readonly Name: string;
  private Running = false;

  /**
   * @param Context Contexto del realm observado. En los realms de iframes (RealmMonitor)
   * es un contexto hijo que reenvía los eventos al principal.
   */
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
    // Se marca como detenido antes de OnStop: las verificaciones periódicas (CheckNow)
    // consultan IsRunning y no deben ejecutarse sobre un estado a medio liberar.
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
   * Retira toda observación y libera recursos. Debe tolerar llamadas sin OnStart previo
   * (o con un OnStart incompleto).
   */
  protected abstract OnStop(): void;
}
