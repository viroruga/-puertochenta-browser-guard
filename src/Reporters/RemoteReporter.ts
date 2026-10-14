import type { ResolvedRemoteConfig } from "../Types/BrowserGuardConfig";
import type { RemotePayload, RemotePayloadSchemaName, RemoteStats } from "../Types/Remote";
import type { SecurityFinding } from "../Types/SecurityFinding";
import { IsSeverityAtLeast } from "../Types/Severity";
import { CreateSessionId } from "../Utils/IdGenerator";
import type { RemoteTransportLike } from "./RemoteTransport";
import { KeepaliveLimitChars } from "./RemoteTransport";
import type { Reporter } from "./Reporter";

/** Identificador del formato del payload, para versionarlo en el backend. */
export const RemotePayloadSchema: RemotePayloadSchemaName = "browser-guard.findings/v1";

/** Espera máxima entre reintentos, en ms (tope del backoff exponencial). */
export const MaxBackoffMs = 60_000;

/** Lote extraído de la cola. */
interface Batch {
  /** Hallazgos incluidos (para reencolarlos si hay que reintentar). */
  Findings: SecurityFinding[];
  /** Cuerpo JSON (RemotePayload) listo para enviar. */
  Body: string;
}

type RemoteWindow = Window & typeof globalThis;

/**
 * Envía hallazgos a un endpoint propio, en lotes y con reintentos.
 *
 * - Sin trabajo pendiente no hay timers activos: el envío se programa al recibir
 *   el primer hallazgo de un lote.
 * - Un lote se envía al alcanzar BatchSize, al vencer FlushIntervalMs, al ocultar o
 *   cerrar la página (sendBeacon) o al detener BrowserGuard.
 * - Errores transitorios se reintentan con backoff exponencial; la cola está acotada
 *   por MaxQueue y cada payload por ~60 KB (límite de keepalive/sendBeacon).
 */
export class RemoteReporter implements Reporter {
  public readonly Name = "RemoteReporter";
  /** Hallazgos pendientes, del más antiguo al más nuevo. */
  private Queue: SecurityFinding[] = [];
  /** Envío programado (intervalo o backoff), o null. Nunca hay más de uno. */
  private Timer: ReturnType<typeof setTimeout> | null = null;
  /** Hay un Send() en curso: evita envíos concurrentes y lotes duplicados. */
  private Sending = false;
  private Disposed = false;
  /** Reintentos consecutivos del lote actual; se reinicia al terminar con éxito o fallo. */
  private Attempt = 0;
  private readonly Stats = { Sent: 0, Dropped: 0, Failed: 0 };
  private readonly SetTimer: typeof setTimeout;
  private readonly ClearTimer: typeof clearTimeout;

  // pagehide y visibilitychange→hidden son los únicos eventos fiables de salida en móviles
  // (unload/beforeunload no se disparan siempre). Se escuchan ambos; enviar dos veces no
  // ocurre porque FlushOnExit vacía la cola.
  private readonly OnPageHide = (): void => {
    this.FlushOnExit();
  };
  private readonly OnVisibilityChange = (): void => {
    if (this.Window.document.visibilityState === "hidden") {
      this.FlushOnExit();
    }
  };

  /**
   * @param Config configuración remota ya resuelta.
   * @param Transport mecanismo de envío (RemoteTransport, o un doble en tests).
   * @param Window ventana de la página (eventos de salida, timers y location).
   * @param SessionId id de la sesión de BrowserGuard, para correlacionar con el header de
   *   veredicto; uno nuevo si no se indica.
   */
  public constructor(
    private readonly Config: ResolvedRemoteConfig,
    private readonly Transport: RemoteTransportLike,
    private readonly Window: RemoteWindow,
    private readonly SessionId: string = CreateSessionId(),
  ) {
    // Referencias propias: un reemplazo posterior de setTimeout no afecta los envíos.
    this.SetTimer = Window.setTimeout.bind(Window) as typeof setTimeout;
    this.ClearTimer = Window.clearTimeout.bind(Window);
    Window.addEventListener("pagehide", this.OnPageHide);
    Window.document.addEventListener("visibilitychange", this.OnVisibilityChange);
  }

  /** Encola un hallazgo (si alcanza MinSeverity) y programa o dispara el envío. */
  public Report(finding: SecurityFinding): void {
    if (this.Disposed || !IsSeverityAtLeast(finding.Severity, this.Config.MinSeverity)) {
      return;
    }
    this.Queue.push(finding);
    this.TrimQueue();
    if (this.Queue.length >= this.Config.BatchSize) {
      void this.Flush();
    } else {
      this.Schedule(this.Config.FlushIntervalMs);
    }
  }

  /**
   * Envía un lote. Si quedan hallazgos, programa el siguiente envío.
   */
  public async Flush(): Promise<void> {
    if (this.Sending || this.Queue.length === 0) {
      return;
    }
    this.CancelTimer();
    this.Sending = true;
    try {
      const batch = this.TakeBatch();
      if (batch.Findings.length === 0) {
        return;
      }
      const result = await this.Transport.Send(batch.Body);
      if (result.Ok) {
        this.Stats.Sent += batch.Findings.length;
        this.Attempt = 0;
      } else if (result.Retryable && this.Attempt < this.Config.MaxRetries && !this.Disposed) {
        this.Attempt++;
        // Se reencola al frente para conservar el orden; TrimQueue descarta los más
        // antiguos si la cola se llenó mientras tanto.
        this.Queue.unshift(...batch.Findings);
        this.TrimQueue();
        this.CancelTimer();
        // Backoff exponencial: FlushIntervalMs × 2^intento, con tope MaxBackoffMs.
        this.Schedule(Math.min(MaxBackoffMs, this.Config.FlushIntervalMs * 2 ** this.Attempt));
        return;
      } else {
        this.Stats.Failed += batch.Findings.length;
        this.Attempt = 0;
      }
    } finally {
      this.Sending = false;
    }
    this.ContinueAfterSend();
  }

  /** Contadores para GetStatus().Remote. */
  public GetStats(): RemoteStats {
    return { Queued: this.Queue.length, ...this.Stats };
  }

  /**
   * Al detener BrowserGuard: envía lo pendiente y libera listeners y timers.
   */
  public Dispose(): void {
    this.Window.removeEventListener("pagehide", this.OnPageHide);
    this.Window.document.removeEventListener("visibilitychange", this.OnVisibilityChange);
    this.FlushOnExit();
    this.Disposed = true;
  }

  /** Tras un envío terminado: sigue con un lote lleno o programa el próximo. */
  private ContinueAfterSend(): void {
    if (this.Disposed || this.Queue.length === 0) {
      return;
    }
    if (this.Queue.length >= this.Config.BatchSize) {
      void this.Flush();
    } else {
      this.Schedule(this.Config.FlushIntervalMs);
    }
  }

  /**
   * Envía toda la cola con un mecanismo que sobrevive al cierre de la página.
   * Síncrono: no hay tiempo para esperar respuestas ni reintentar. Un lote que está en
   * vuelo en un Send() normal no se reenvía (ya no está en la cola).
   */
  private FlushOnExit(): void {
    this.CancelTimer();
    while (this.Queue.length > 0) {
      const batch = this.TakeBatch();
      if (batch.Findings.length === 0) {
        continue;
      }
      if (this.Transport.SendOnExit(batch.Body)) {
        this.Stats.Sent += batch.Findings.length;
      } else {
        this.Stats.Failed += batch.Findings.length;
      }
    }
  }

  /**
   * Extrae de la cola un lote que respete BatchSize y el límite de tamaño.
   * Un hallazgo que no cabe solo se envía sin evidencia ni stack; si aun así no
   * cabe, se descarta. Siempre consume al menos un elemento si la cola no está vacía.
   */
  private TakeBatch(): Batch {
    const envelope = JSON.stringify(this.CreateEnvelope());
    // Tamaño fijo del cuerpo: el sobre más `,"Findings":[]` (misma longitud que el literal).
    const base = envelope.length + '"Findings":[],'.length;
    const findings: SecurityFinding[] = [];
    const parts: string[] = [];
    let size = base;

    while (this.Queue.length > 0 && findings.length < this.Config.BatchSize) {
      const finding = this.Queue[0] as SecurityFinding;
      let serialized = JSON.stringify(this.Prepare(finding, false));
      if (base + serialized.length > KeepaliveLimitChars) {
        serialized = JSON.stringify(this.Prepare(finding, true));
        if (base + serialized.length > KeepaliveLimitChars) {
          this.Queue.shift();
          this.Stats.Dropped++;
          continue;
        }
      }
      // +1 por la coma separadora. Si no cabe, queda para el próximo lote.
      if (size + serialized.length + 1 > KeepaliveLimitChars) {
        break;
      }
      this.Queue.shift();
      findings.push(finding);
      parts.push(serialized);
      size += serialized.length + 1;
    }

    // Se arma el JSON a mano (sobre sin su "}" final + Findings) para no volver a
    // serializar cada hallazgo, que ya se serializó para medirlo.
    return {
      Findings: findings,
      Body: `${envelope.slice(0, -1)},"Findings":[${parts.join(",")}]}`,
    };
  }

  /** Campos del payload comunes a todo el lote. */
  private CreateEnvelope(): Omit<RemotePayload, "Findings"> {
    const location = this.Window.location;
    const envelope: Omit<RemotePayload, "Findings"> = {
      Schema: RemotePayloadSchema,
      SentAt: Date.now(),
      SessionId: this.SessionId,
      Page: { Origin: location.origin },
    };
    if (this.Config.IncludePagePath) {
      // pathname nunca incluye query string ni fragmento.
      envelope.Page.Path = location.pathname;
    }
    if (Object.keys(this.Config.Metadata).length > 0) {
      envelope.Metadata = this.Config.Metadata;
    }
    return envelope;
  }

  /**
   * Copia del hallazgo para enviar, respetando IncludeEvidence/IncludeStack. Con
   * `minimal` omite siempre Evidence y Stack (los campos potencialmente grandes).
   * La evidencia ya viene saneada por RiskEngine (SafeSerialize).
   */
  private Prepare(finding: SecurityFinding, minimal: boolean): Partial<SecurityFinding> {
    const prepared: Partial<SecurityFinding> = {
      Id: finding.Id,
      Timestamp: finding.Timestamp,
      Category: finding.Category,
      Severity: finding.Severity,
      Title: finding.Title,
      Description: finding.Description,
      RiskScore: finding.RiskScore,
      Signals: finding.Signals,
      EventId: finding.EventId,
    };
    if (!minimal && this.Config.IncludeEvidence && finding.Evidence !== undefined) {
      prepared.Evidence = finding.Evidence;
    }
    if (!minimal && this.Config.IncludeStack && finding.Stack !== undefined) {
      prepared.Stack = finding.Stack;
    }
    return prepared;
  }

  /** Aplica MaxQueue descartando los más antiguos (cuentan como Dropped). */
  private TrimQueue(): void {
    while (this.Queue.length > this.Config.MaxQueue) {
      this.Queue.shift();
      this.Stats.Dropped++;
    }
  }

  /**
   * Programa un Flush si no hay uno programado. Con un timer activo no lo reprograma:
   * así el primer hallazgo de un lote fija el plazo y un backoff no se acorta.
   */
  private Schedule(delayMs: number): void {
    if (this.Timer !== null || this.Disposed) {
      return;
    }
    this.Timer = this.SetTimer(() => {
      this.Timer = null;
      void this.Flush();
    }, delayMs);
  }

  private CancelTimer(): void {
    if (this.Timer !== null) {
      this.ClearTimer(this.Timer);
      this.Timer = null;
    }
  }
}
