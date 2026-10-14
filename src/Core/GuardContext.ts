import type { ResolvedConfig } from "../Types/BrowserGuardConfig";
import type {
  SecurityEventDataMap,
  SecurityEventType,
  TypedSecurityEvent,
} from "../Types/SecurityEvent";
import { CreateId, CreateSessionId } from "../Utils/IdGenerator";

/**
 * Cantidad máxima de eventos pendientes de procesar.
 * Ante una ráfaga anómala se descartan eventos en lugar de crecer sin límite.
 */
export const MaxPendingEvents = 1000;

/** Evento de cualquier tipo, tal como circula por la cola. */
type AnySecurityEvent = TypedSecurityEvent<SecurityEventType>;

/**
 * Decide qué header agregar a una solicitud saliente (o ninguno).
 * Recibe la URL tal como la pasó la aplicación (null si no se pudo determinar) y
 * retorna el par [nombre, valor]. Lo registra AntiScrapingController; lo consultan
 * los monitores de fetch y XHR.
 */
export type RequestHeaderProvider = (url: string | null) => readonly [string, string] | null;

/**
 * Contexto compartido por monitores durante una sesión de BrowserGuard.
 *
 * Es el único canal entre los monitores y el resto del pipeline: los monitores no
 * conocen el EventBus ni los detectores, solo llaman a Emit(). BrowserGuard lo crea en
 * Start() con la función que despacha cada evento al EventBus interno; también lo
 * reciben los plugins (PluginHost.Context) y los detectores como PageInfo.
 *
 * Responsabilidades:
 * - exponer la configuración resuelta y el objeto window observado;
 * - construir eventos normalizados y despacharlos en lote (microtask), de modo que
 *   la detección y el reporte nunca se ejecuten dentro de la llamada de la aplicación;
 * - registrar las funciones creadas por BrowserGuard para no auto-detectarlas;
 * - contabilizar errores internos sin propagarlos.
 *
 * Un contexto hijo (CreateChild) observa otro realm (p. ej. un iframe del mismo origen)
 * y delega en el principal: eventos, funciones propias, header de veredicto, sesión,
 * URL de la página y errores.
 */
export class GuardContext {
  /**
   * Proxies y funciones creados por BrowserGuard. WeakSet: no impide que se liberen
   * cuando dejan de estar instalados.
   */
  private readonly OwnFunctions = new WeakSet();
  /** Cola de eventos a despachar en el próximo microtask (solo en el contexto raíz). */
  private Pending: AnySecurityEvent[] = [];
  private FlushScheduled = false;
  /** false tras Dispose(): Emit y GetRequestHeader pasan a no hacer nada. */
  private Active = true;
  private DroppedCount = 0;
  private ErrorCount = 0;
  private HeaderProvider: RequestHeaderProvider | null = null;

  /** Identificador aleatorio de esta sesión de BrowserGuard (compartido con los hijos). */
  public readonly SessionId: string;

  /**
   * @param Config Configuración resuelta (compartida con los contextos hijos).
   * @param Window Realm observado: window principal o el de un iframe.
   * @param Dispatch Entrega un evento al pipeline; se invoca fuera de la llamada de la app.
   * @param Parent Contexto principal, si este es un contexto hijo.
   */
  public constructor(
    public readonly Config: ResolvedConfig,
    public readonly Window: Window & typeof globalThis,
    private readonly Dispatch: (event: AnySecurityEvent) => void,
    private readonly Parent: GuardContext | null = null,
  ) {
    this.SessionId = Parent?.SessionId ?? CreateSessionId();
  }

  /**
   * Contexto para otro realm del mismo origen. Sus monitores reportan a este contexto.
   */
  public CreateChild(window: Window & typeof globalThis): GuardContext {
    return new GuardContext(this.Config, window, this.Dispatch, this);
  }

  /**
   * Base para resolver URLs relativas del realm observado (respeta <base href>; en un
   * iframe about:blank es la del documento que lo creó).
   */
  public GetBaseUrl(): string {
    const base = (this.Window.document as Document | undefined)?.baseURI;
    return base && base !== "about:blank" ? base : this.GetPageUrl();
  }

  /** URL de la página principal (para detectar valores reflejados desde la URL). */
  public GetPageUrl(): string {
    return this.Parent ? this.Parent.GetPageUrl() : this.Window.location.href;
  }

  /** Origen de la página principal (no del iframe): base de "mismo origen" para detectores. */
  public GetPageOrigin(): string {
    return this.Parent ? this.Parent.GetPageOrigin() : this.Window.location.origin;
  }

  /** Protocolo de la página principal (p. ej. para detectar transporte inseguro). */
  public GetPageProtocol(): string {
    return this.Parent ? this.Parent.GetPageProtocol() : this.Window.location.protocol;
  }

  /**
   * Crea y encola un evento. Nunca lanza.
   *
   * Se llama desde dentro de las APIs interceptadas, por lo que hace el mínimo trabajo
   * posible: el análisis ocurre después, en Flush().
   *
   * @param type Tipo del evento; determina la forma de `data`.
   * @param source Nombre del monitor que lo emite.
   * @param data Datos ya saneados por el monitor (nunca contenido sensible).
   * @param stack Stack del código que originó la acción, si el monitor lo capturó.
   */
  public Emit<K extends SecurityEventType>(
    type: K,
    source: string,
    data: SecurityEventDataMap[K],
    stack?: string,
  ): void {
    if (!this.Active) {
      return;
    }
    if (this.Parent) {
      this.Parent.Emit(type, source, data, stack);
      return;
    }
    // Límite de memoria: un script hostil podría provocar millones de eventos para
    // saturar la cola. El descarte queda visible en GetStatus().DroppedEvents.
    if (this.Pending.length >= MaxPendingEvents) {
      this.DroppedCount++;
      return;
    }
    const event = {
      Id: CreateId("evt"),
      Timestamp: Date.now(),
      Type: type,
      Source: source,
      Data: data,
    } as TypedSecurityEvent<K>;
    if (stack !== undefined) {
      event.Stack = stack;
    }
    this.Pending.push(event);
    this.ScheduleFlush();
  }

  /**
   * Procesa inmediatamente los eventos pendientes.
   * Normalmente lo invoca el microtask programado; BrowserGuard.Stop() lo llama
   * directamente para no perder los eventos capturados antes de detenerse.
   */
  public Flush(): void {
    this.FlushScheduled = false;
    // Se toma el lote y se vacía la cola antes de despachar: los eventos que se emitan
    // durante el despacho van a un lote nuevo (con su propio microtask).
    const batch = this.Pending;
    this.Pending = [];
    for (const event of batch) {
      // Un detector o reporter puede haber detenido BrowserGuard durante el lote.
      if (!this.Active) {
        return;
      }
      try {
        this.Dispatch(event);
      } catch (error) {
        this.ReportInternalError(error);
      }
    }
  }

  /**
   * Registra quién decide los headers de las solicitudes salientes (anti-scraping).
   */
  public SetRequestHeaderProvider(provider: RequestHeaderProvider | null): void {
    this.HeaderProvider = provider;
  }

  /**
   * Header a agregar a una solicitud, o null. Nunca lanza.
   * En un contexto hijo delega en el principal, que es donde se registra el proveedor.
   */
  public GetRequestHeader(url: string | null): readonly [string, string] | null {
    if (this.Parent) {
      return this.Active ? this.Parent.GetRequestHeader(url) : null;
    }
    if (!this.Active || !this.HeaderProvider) {
      return null;
    }
    try {
      return this.HeaderProvider(url);
    } catch (error) {
      this.ReportInternalError(error);
      return null;
    }
  }

  /**
   * Marca una función (o proxy) como creada por BrowserGuard, para que RuntimeMonitor
   * no la confunda con una modificación hecha por terceros.
   */
  public RegisterOwnFunction(fn: object): void {
    if (this.Parent) {
      this.Parent.RegisterOwnFunction(fn);
      return;
    }
    this.OwnFunctions.add(fn);
  }

  /** Indica si un valor fue registrado con RegisterOwnFunction (en cualquier realm). */
  public IsOwnFunction(value: unknown): boolean {
    if (this.Parent) {
      return this.Parent.IsOwnFunction(value);
    }
    // WeakSet.has solo admite objetos: los primitivos nunca son funciones propias.
    return typeof value === "function" || (typeof value === "object" && value !== null)
      ? this.OwnFunctions.has(value)
      : false;
  }

  /**
   * Registra un error interno. Nunca se propaga a la aplicación host.
   * Solo se cuenta (GetStatus().InternalErrors): el error puede contener datos de la
   * aplicación y no se retiene ni se imprime.
   */
  public ReportInternalError(error: unknown): void {
    if (this.Parent) {
      this.Parent.ReportInternalError(error);
      return;
    }
    this.ErrorCount++;
  }

  /**
   * Ejecuta una función protegiendo a la aplicación de errores internos.
   */
  public Safely(work: () => void): void {
    try {
      work();
    } catch (error) {
      this.ReportInternalError(error);
    }
  }

  /** Eventos descartados por cola llena desde el inicio. */
  public get DroppedEvents(): number {
    return this.DroppedCount;
  }

  /** Errores internos contabilizados (incluye los de los contextos hijos). */
  public get InternalErrors(): number {
    return this.ErrorCount;
  }

  public IsActive(): boolean {
    return this.Active;
  }

  /**
   * Desactiva el contexto y descarta eventos pendientes.
   */
  public Dispose(): void {
    this.Active = false;
    this.Pending = [];
  }

  /**
   * Programa un único Flush por lote. Microtask y no setTimeout: los eventos se
   * procesan apenas termina el código síncrono de la aplicación, sin ceder el turno
   * a otras tareas, y queueMicrotask no es una API que los monitores intercepten.
   */
  private ScheduleFlush(): void {
    if (this.FlushScheduled) {
      return;
    }
    this.FlushScheduled = true;
    queueMicrotask(() => {
      this.Flush();
    });
  }
}
