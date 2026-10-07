/**
 * Manejador de un evento con payload tipado.
 */
export type EventHandler<T> = (payload: T) => void;

/**
 * Manejador sin tipo concreto, usado solo para almacenamiento interno.
 * Cualquier EventHandler<T> es asignable a este tipo.
 */
type StoredHandler = EventHandler<never>;

/**
 * Bus de eventos liviano y tipado.
 *
 * - Las excepciones de un manejador nunca interrumpen a los demás ni se propagan
 *   al emisor; se notifican mediante el callback OnError.
 * - Se itera sobre una copia del conjunto de manejadores, por lo que es seguro
 *   suscribirse o desuscribirse durante una emisión.
 */
export class EventBus<TEvents extends Record<string, unknown>> {
  private readonly Handlers = new Map<keyof TEvents, Set<StoredHandler>>();
  private readonly OnceWrappers = new Map<keyof TEvents, Map<StoredHandler, StoredHandler>>();

  public constructor(private readonly OnError?: (error: unknown, event: keyof TEvents) => void) {}

  /**
   * Suscribe un manejador. Retorna una función para desuscribirlo.
   */
  public On<K extends keyof TEvents>(event: K, handler: EventHandler<TEvents[K]>): () => void {
    let handlers = this.Handlers.get(event);
    if (!handlers) {
      handlers = new Set();
      this.Handlers.set(event, handlers);
    }
    handlers.add(handler);
    return () => {
      this.Off(event, handler);
    };
  }

  /**
   * Suscribe un manejador que se ejecuta una única vez.
   */
  public Once<K extends keyof TEvents>(event: K, handler: EventHandler<TEvents[K]>): () => void {
    const wrapper: EventHandler<TEvents[K]> = (payload) => {
      this.Off(event, handler);
      handler(payload);
    };
    let wrappers = this.OnceWrappers.get(event);
    if (!wrappers) {
      wrappers = new Map();
      this.OnceWrappers.set(event, wrappers);
    }
    wrappers.set(handler, wrapper);
    this.On(event, wrapper);
    return () => {
      this.Off(event, handler);
    };
  }

  /**
   * Desuscribe un manejador (registrado con On u Once).
   */
  public Off<K extends keyof TEvents>(event: K, handler: EventHandler<TEvents[K]>): void {
    const handlers = this.Handlers.get(event);
    if (!handlers) {
      return;
    }
    handlers.delete(handler);

    const wrappers = this.OnceWrappers.get(event);
    const wrapper = wrappers?.get(handler);
    if (wrappers && wrapper) {
      handlers.delete(wrapper);
      wrappers.delete(handler);
      if (wrappers.size === 0) {
        this.OnceWrappers.delete(event);
      }
    }

    if (handlers.size === 0) {
      this.Handlers.delete(event);
    }
  }

  /**
   * Emite un evento de forma síncrona a todos los manejadores suscritos.
   */
  public Emit<K extends keyof TEvents>(event: K, payload: TEvents[K]): void {
    const handlers = this.Handlers.get(event);
    if (!handlers || handlers.size === 0) {
      return;
    }
    for (const handler of [...handlers]) {
      try {
        (handler as EventHandler<TEvents[K]>)(payload);
      } catch (error) {
        this.OnError?.(error, event);
      }
    }
  }

  /**
   * Cantidad de manejadores de un evento, o de todos si no se indica.
   */
  public ListenerCount(event?: keyof TEvents): number {
    if (event !== undefined) {
      return this.Handlers.get(event)?.size ?? 0;
    }
    let total = 0;
    for (const handlers of this.Handlers.values()) {
      total += handlers.size;
    }
    return total;
  }

  /**
   * Elimina todos los manejadores.
   */
  public Clear(): void {
    this.Handlers.clear();
    this.OnceWrappers.clear();
  }
}
