import type { GuardSnapshot } from "../Types/GuardStatus";

/**
 * Store observable con snapshots inmutables.
 *
 * Lo crea BrowserGuard y lo expone como Subscribe/GetSnapshot; BrowserGuard llama a
 * Update() cuando cambia el estado de ejecución, el veredicto de bot o llega un hallazgo.
 *
 * Es el contrato que consumen los frameworks sin adaptadores específicos:
 * - React: useSyncExternalStore(Guard.Subscribe, Guard.GetSnapshot);
 * - Vue: un ref actualizado desde Subscribe;
 * - Angular: un signal actualizado desde Subscribe;
 * - Svelte:
 *   readable(Guard.GetSnapshot(), (set) => Guard.Subscribe(() => set(Guard.GetSnapshot()))).
 *
 * El snapshot solo cambia de identidad en Update(), y BrowserGuard solo lo invoca
 * cuando algo cambió; entre actualizaciones GetSnapshot() retorna la misma referencia,
 * por lo que los frameworks pueden comparar por referencia sin renderizar de más.
 * (Update() no compara contenidos: cada llamada produce un snapshot nuevo.)
 */
export class GuardStore {
  private Snapshot: GuardSnapshot;
  private readonly Listeners = new Set<() => void>();

  /**
   * @param initial Snapshot inicial (se copia y congela).
   * @param OnListenerError Recibe los errores de los listeners de la aplicación.
   */
  public constructor(
    initial: GuardSnapshot,
    private readonly OnListenerError: (error: unknown) => void,
  ) {
    this.Snapshot = Object.freeze({ ...initial });
  }

  // Get y Subscribe son propiedades flecha (no métodos) para que puedan pasarse sueltas,
  // p. ej. a useSyncExternalStore, sin perder `this`.

  /** Snapshot actual. */
  public readonly Get = (): GuardSnapshot => this.Snapshot;

  /** Suscribe un listener sin argumentos; retorna la función para desuscribirlo. */
  public readonly Subscribe = (listener: () => void): (() => void) => {
    this.Listeners.add(listener);
    return () => {
      this.Listeners.delete(listener);
    };
  };

  /** Publica un snapshot nuevo y notifica a los suscriptores. */
  public Update(patch: Partial<GuardSnapshot>): void {
    this.Snapshot = Object.freeze({ ...this.Snapshot, ...patch });
    // Copia: un listener puede desuscribirse al ser notificado. Un listener que falla
    // no impide notificar a los demás.
    for (const listener of [...this.Listeners]) {
      try {
        listener();
      } catch (error) {
        this.OnListenerError(error);
      }
    }
  }
}
