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

type AnySecurityEvent = TypedSecurityEvent<SecurityEventType>;

/**
 * Decide qué header agregar a una solicitud saliente (o ninguno).
 */
export type RequestHeaderProvider = (url: string | null) => readonly [string, string] | null;

/**
 * Contexto compartido por monitores durante una sesión de BrowserGuard.
 *
 * Responsabilidades:
 * - exponer la configuración resuelta y el objeto window observado;
 * - construir eventos normalizados y despacharlos en lote (microtask), de modo que
 *   la detección y el reporte nunca se ejecuten dentro de la llamada de la aplicación;
 * - registrar las funciones creadas por BrowserGuard para no auto-detectarlas;
 * - contabilizar errores internos sin propagarlos.
 */
export class GuardContext {
  private readonly OwnFunctions = new WeakSet();
  private Pending: AnySecurityEvent[] = [];
  private FlushScheduled = false;
  private Active = true;
  private DroppedCount = 0;
  private ErrorCount = 0;
  private HeaderProvider: RequestHeaderProvider | null = null;

  /** Identificador aleatorio de esta sesión de BrowserGuard. */
  public readonly SessionId = CreateSessionId();

  public constructor(
    public readonly Config: ResolvedConfig,
    public readonly Window: Window & typeof globalThis,
    private readonly Dispatch: (event: AnySecurityEvent) => void,
  ) {}

  /** URL actual de la página, usada como base para URLs relativas. */
  public GetBaseUrl(): string {
    return this.Window.location.href;
  }

  public GetPageOrigin(): string {
    return this.Window.location.origin;
  }

  public GetPageProtocol(): string {
    return this.Window.location.protocol;
  }

  /**
   * Crea y encola un evento. Nunca lanza.
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
   */
  public Flush(): void {
    this.FlushScheduled = false;
    const batch = this.Pending;
    this.Pending = [];
    for (const event of batch) {
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
   */
  public GetRequestHeader(url: string | null): readonly [string, string] | null {
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

  public RegisterOwnFunction(fn: object): void {
    this.OwnFunctions.add(fn);
  }

  public IsOwnFunction(value: unknown): boolean {
    return typeof value === "function" || (typeof value === "object" && value !== null)
      ? this.OwnFunctions.has(value)
      : false;
  }

  /**
   * Registra un error interno. Nunca se propaga a la aplicación host.
   */
  public ReportInternalError(_error: unknown): void {
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

  public get DroppedEvents(): number {
    return this.DroppedCount;
  }

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
