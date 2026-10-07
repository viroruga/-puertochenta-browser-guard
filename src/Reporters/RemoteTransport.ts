/**
 * Resultado de un envío.
 */
export interface TransportResult {
  Ok: boolean;
  /** El error es transitorio y conviene reintentar (red, 5xx, 408, 429). */
  Retryable: boolean;
  Status?: number;
}

/**
 * Contrato del transporte. Permite sustituirlo en tests o por implementaciones propias.
 */
export interface RemoteTransportLike {
  Send(body: string): Promise<TransportResult>;
  /** Envío "fire and forget" apto para el cierre de la página. Retorna si fue aceptado. */
  SendOnExit(body: string): boolean;
}

/** Límite de cuerpo para keepalive / sendBeacon (los navegadores aceptan ~64 KB). */
export const KeepaliveLimitChars = 60_000;

type BeaconFunction = (url: string, data: BodyInit) => boolean;

export function IsRetryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

/**
 * Transporte HTTP de hallazgos.
 *
 * - Usa una referencia a `fetch` capturada al construirse. BrowserGuard crea los
 *   reporters antes de iniciar los monitores, por lo que es el fetch original: los
 *   envíos propios no son interceptados ni generan hallazgos (sin bucles).
 * - `credentials: "omit"`: nunca envía cookies del usuario.
 * - `referrerPolicy: "no-referrer"`: la URL completa de la página (que puede tener
 *   tokens en la query) no viaja en el header Referer.
 * - Al cerrar la página usa sendBeacon (text/plain, sin preflight CORS) si no hay
 *   headers personalizados; si los hay, usa fetch con keepalive.
 */
export class RemoteTransport implements RemoteTransportLike {
  private readonly Fetch: typeof fetch | null;
  private readonly Beacon: BeaconFunction | null;

  public constructor(
    private readonly Endpoint: string,
    private readonly Headers: Record<string, string>,
    window: Window & typeof globalThis,
  ) {
    this.Fetch = typeof window.fetch === "function" ? window.fetch.bind(window) : null;
    const navigator = window.navigator as Navigator | undefined;
    this.Beacon =
      typeof navigator?.sendBeacon === "function" ? navigator.sendBeacon.bind(navigator) : null;
  }

  public async Send(body: string): Promise<TransportResult> {
    if (!this.Fetch) {
      return { Ok: false, Retryable: false };
    }
    try {
      const response = await this.Fetch(this.Endpoint, this.CreateInit(body));
      return {
        Ok: response.ok,
        Retryable: !response.ok && IsRetryableStatus(response.status),
        Status: response.status,
      };
    } catch {
      return { Ok: false, Retryable: true };
    }
  }

  public SendOnExit(body: string): boolean {
    if (this.Beacon && Object.keys(this.Headers).length === 0) {
      try {
        const blob = new Blob([body], { type: "text/plain;charset=UTF-8" });
        if (this.Beacon(this.Endpoint, blob)) {
          return true;
        }
      } catch {
        // Se intenta con fetch keepalive.
      }
    }
    if (!this.Fetch) {
      return false;
    }
    try {
      this.Fetch(this.Endpoint, this.CreateInit(body)).catch(() => undefined);
      return true;
    } catch {
      return false;
    }
  }

  private CreateInit(body: string): RequestInit {
    return {
      method: "POST",
      headers: { "Content-Type": "application/json", ...this.Headers },
      body,
      keepalive: body.length <= KeepaliveLimitChars,
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    };
  }
}
