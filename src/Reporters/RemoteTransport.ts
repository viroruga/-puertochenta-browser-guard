/**
 * Transporte HTTP del envío remoto (plugin RemoteReporting). RemoteReporter decide qué y
 * cuándo enviar; este módulo solo sabe cómo hacerlo de forma segura.
 */

/**
 * Resultado de un envío.
 */
export interface TransportResult {
  /** Respuesta 2xx. */
  Ok: boolean;
  /** El error es transitorio y conviene reintentar (red, 5xx, 408, 429). */
  Retryable: boolean;
  /** Código HTTP, si hubo respuesta. */
  Status?: number;
}

/**
 * Contrato del transporte. Permite sustituirlo en tests o por implementaciones propias.
 */
export interface RemoteTransportLike {
  /** Envío normal; la promesa nunca se rechaza. */
  Send(body: string): Promise<TransportResult>;
  /** Envío "fire and forget" apto para el cierre de la página. Retorna si fue aceptado. */
  SendOnExit(body: string): boolean;
}

/**
 * Límite de cuerpo para keepalive / sendBeacon (los navegadores aceptan ~64 KB). Se
 * mide en caracteres UTF-16, no en bytes: el margen hasta 64 KB cubre el texto ASCII
 * habitual, pero mucho texto no ASCII podría superarlo.
 */
export const KeepaliveLimitChars = 60_000;

type BeaconFunction = (url: string, data: BodyInit) => boolean;

/**
 * Estados que vale la pena reintentar: timeout (408), rate limit (429) y errores del
 * servidor (5xx). Los demás 4xx indican un problema de configuración y no se reintentan.
 */
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
  /** fetch original (ligado a window), o null si el entorno no lo tiene. */
  private readonly Fetch: typeof fetch | null;
  /** navigator.sendBeacon ligado, o null si no existe. */
  private readonly Beacon: BeaconFunction | null;

  /**
   * @param Endpoint URL ya validada por la configuración (https, mismo origen o localhost).
   * @param Headers headers adicionales de RemoteConfig.Headers.
   */
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
      // fetch solo rechaza por error de red (o CORS): transitorio.
      return { Ok: false, Retryable: true };
    }
  }

  public SendOnExit(body: string): boolean {
    // sendBeacon no admite headers propios: con headers configurados se usa fetch keepalive.
    if (this.Beacon && Object.keys(this.Headers).length === 0) {
      try {
        // text/plain es un tipo "simple" para CORS: un endpoint de otro origen no requiere
        // preflight (que no llegaría a completarse al cerrar la página). El cuerpo sigue
        // siendo JSON; el backend debe parsearlo sin fiarse del Content-Type.
        const blob = new Blob([body], { type: "text/plain;charset=UTF-8" });
        // false = el navegador no lo encoló (p. ej. cuota de keepalive agotada).
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
      // Sin await: la página se está cerrando. "true" significa solo que se intentó; un
      // fallo posterior no se contabiliza.
      this.Fetch(this.Endpoint, this.CreateInit(body)).catch(() => undefined);
      return true;
    } catch {
      return false;
    }
  }

  /** Opciones de fetch comunes a todos los envíos. */
  private CreateInit(body: string): RequestInit {
    return {
      method: "POST",
      headers: { "Content-Type": "application/json", ...this.Headers },
      body,
      // keepalive permite que la solicitud sobreviva al cierre de la página, pero los
      // navegadores rechazan cuerpos mayores a ~64 KB con keepalive.
      keepalive: body.length <= KeepaliveLimitChars,
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    };
  }
}
