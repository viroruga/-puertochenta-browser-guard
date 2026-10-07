import type { GuardSnapshot } from "../Types/GuardStatus";

/**
 * Store observable con snapshots inmutables.
 *
 * Es el contrato que consumen los frameworks sin adaptadores específicos:
 * - React: useSyncExternalStore(Guard.Subscribe, Guard.GetSnapshot);
 * - Vue: un ref actualizado desde Subscribe;
 * - Angular: un signal actualizado desde Subscribe;
 * - Svelte: readable(Guard.GetSnapshot(), (set) => Guard.Subscribe(() => set(Guard.GetSnapshot()))).
 *
 * El snapshot solo cambia de identidad cuando cambia su contenido, por lo que los
 * frameworks pueden comparar por referencia sin renderizar de más.
 */
export class GuardStore {
  private Snapshot: GuardSnapshot;
  private readonly Listeners = new Set<() => void>();

  public constructor(
    initial: GuardSnapshot,
    private readonly OnListenerError: (error: unknown) => void,
  ) {
    this.Snapshot = Object.freeze({ ...initial });
  }

  public readonly Get = (): GuardSnapshot => this.Snapshot;

  public readonly Subscribe = (listener: () => void): (() => void) => {
    this.Listeners.add(listener);
    return () => {
      this.Listeners.delete(listener);
    };
  };

  /** Publica un snapshot nuevo y notifica a los suscriptores. */
  public Update(patch: Partial<GuardSnapshot>): void {
    this.Snapshot = Object.freeze({ ...this.Snapshot, ...patch });
    for (const listener of [...this.Listeners]) {
      try {
        listener();
      } catch (error) {
        this.OnListenerError(error);
      }
    }
  }
}
