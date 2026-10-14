import type { ProofState } from "../Types/Bot";
import { ClampDifficulty, SolveWork } from "../Utils/ProofOfWork";

/**
 * Renovar el desafío este tiempo antes de que venza, para que nunca haya un hueco sin
 * prueba vigente mientras se resuelve el siguiente.
 */
export const RefreshMarginMs = 60_000;
/**
 * Espera mínima entre renovaciones. Si el servidor emite desafíos con un TTL menor que
 * RefreshMarginMs, evita pedir y resolver desafíos en un bucle continuo.
 */
const MinRefreshDelayMs = 10_000;
/** Esperas tras fallos consecutivos; el último valor se repite indefinidamente. */
const RetryDelaysMs: readonly number[] = [5_000, 30_000, 120_000, 300_000];

/** Respuesta del endpoint (ver CreateChallenge en el subpath /server). */
interface ChallengeResponse {
  /** Desafío firmado por el servidor (opaco para el cliente). */
  Challenge: string;
  /** Bits en cero exigidos al hash; se acota con ClampDifficulty antes de resolver. */
  Difficulty: number;
  /** Vencimiento del desafío, en ms desde epoch. */
  ExpiresAt: number;
}

/**
 * Valida la forma de la respuesta sin confiar en ella: el endpoint podría estar mal
 * configurado o comprometido. El largo máximo acota la prueba que luego viaja en un header.
 */
function ParseResponse(value: unknown): ChallengeResponse | null {
  const data = value as Partial<ChallengeResponse> | null;
  return typeof data?.Challenge === "string" &&
    data.Challenge.length <= 2048 &&
    typeof data.Difficulty === "number" &&
    typeof data.ExpiresAt === "number"
    ? (data as ChallengeResponse)
    : null;
}

/**
 * Obtiene, resuelve y renueva el desafío del servidor.
 *
 * - Usa el fetch y los timers capturados al construirse (antes de que BrowserGuard los
 *   intercepte): sus solicitudes no generan hallazgos ni pasan por hooks de la página.
 * - La prueba de trabajo es asíncrona y por lotes: no bloquea la interfaz.
 * - Renueva el desafío antes de que venza y reintenta con espera creciente si falla.
 *
 * La prueba ("<desafío>~<nonce>") viaja en el header de veredicto (`proof=`), así que
 * solo llega al servidor con VerdictHeader habilitado; el servidor la verifica
 * con VerifyProof. Su función es encarecer el scraping masivo: cada sesión debe gastar
 * CPU, y el desafío firmado y ligado al id de sesión no se puede reutilizar entre sesiones.
 */
export class ChallengeClient {
  private readonly Fetch: typeof fetch | null;
  private readonly SetTimer: (callback: () => void, delay: number) => number;
  private readonly ClearTimer: (id: number) => void;
  private StateValue: ProofState = "pending";
  /** Última prueba resuelta; puede estar vencida (GetProof lo verifica). */
  private Proof: string | null = null;
  private ExpiresAt = 0;
  private Timer: number | null = null;
  /** Fallos consecutivos: índice en RetryDelaysMs. */
  private Failures = 0;
  /** Señal compartida con SolveWork para cortar la prueba de trabajo al hacer Dispose. */
  private readonly Cancellation = { aborted: false };

  /**
   * @param Endpoint URL ya validada por ResolveEndpoint (https, mismo origen o localhost).
   * @param SessionId id de sesión de BrowserGuard; el servidor liga el desafío a él.
   * @param OnStateChange se invoca solo cuando cambia el estado (pending/ready/failed).
   */
  public constructor(
    private readonly Endpoint: string,
    private readonly SessionId: string,
    window: Window & typeof globalThis,
    private readonly OnStateChange: (state: ProofState) => void = () => undefined,
  ) {
    // Referencias capturadas aquí, antes de que los monitores parcheen fetch/setTimeout.
    this.Fetch = typeof window.fetch === "function" ? window.fetch.bind(window) : null;
    this.SetTimer = window.setTimeout.bind(window) as (
      callback: () => void,
      delay: number,
    ) => number;
    this.ClearTimer = window.clearTimeout.bind(window);
  }

  /** Pide y resuelve el primer desafío en segundo plano (no espera el resultado). */
  public Start(): void {
    void this.Refresh();
  }

  /** Estado de la prueba, publicado en el veredicto (BotAssessment.Proof). */
  public GetState(): ProofState {
    return this.StateValue;
  }

  /** Prueba vigente, o null si aún no está lista o venció. */
  public GetProof(): string | null {
    return this.Proof !== null && Date.now() < this.ExpiresAt ? this.Proof : null;
  }

  /** Cancela la prueba en curso y los timers pendientes. Es definitivo. */
  public Dispose(): void {
    this.Cancellation.aborted = true;
    if (this.Timer !== null) {
      this.ClearTimer(this.Timer);
      this.Timer = null;
    }
  }

  /** Cambia el estado y notifica solo si es distinto (evita snapshots redundantes). */
  private SetState(state: ProofState): void {
    if (state === this.StateValue) {
      return;
    }
    this.StateValue = state;
    this.OnStateChange(state);
  }

  /**
   * Un ciclo completo: pedir desafío, resolverlo, guardar la prueba y programar la
   * renovación (o un reintento con espera creciente si algo falla).
   */
  private async Refresh(): Promise<void> {
    if (this.Cancellation.aborted) {
      return;
    }
    // Al renovar se conserva "ready": la prueba anterior sigue vigente mientras tanto.
    if (this.StateValue !== "ready") {
      this.SetState("pending");
    }
    try {
      const challenge = await this.Request();
      const nonce = await SolveWork(
        challenge.Challenge,
        ClampDifficulty(challenge.Difficulty),
        this.Cancellation,
      );
      // null: cancelado por Dispose; no hay nada más que hacer.
      if (nonce === null) {
        return;
      }
      this.Proof = `${challenge.Challenge}~${nonce}`;
      this.ExpiresAt = challenge.ExpiresAt;
      this.SetState("ready");
      this.Failures = 0;
      this.Schedule(
        Math.max(MinRefreshDelayMs, challenge.ExpiresAt - Date.now() - RefreshMarginMs),
      );
    } catch {
      // Un fallo al renovar no invalida una prueba que todavía no venció.
      this.SetState(this.GetProof() !== null ? "ready" : "failed");
      const delay = RetryDelaysMs[Math.min(this.Failures, RetryDelaysMs.length - 1)] ?? 300_000;
      this.Failures++;
      this.Schedule(delay);
    }
  }

  /** Pide un desafío para esta sesión. Lanza ante cualquier problema (lo maneja Refresh). */
  private async Request(): Promise<ChallengeResponse> {
    if (!this.Fetch) {
      throw new Error("fetch is not available");
    }
    const separator = this.Endpoint.includes("?") ? "&" : "?";
    // no-store: un desafío cacheado podría estar vencido o pertenecer a otra sesión.
    // same-origin: solo envía cookies al propio sitio, nunca a un endpoint de terceros.
    const response = await this.Fetch(
      `${this.Endpoint}${separator}sid=${encodeURIComponent(this.SessionId)}`,
      { method: "GET", cache: "no-store", credentials: "same-origin" },
    );
    if (!response.ok) {
      throw new Error(`challenge endpoint responded ${String(response.status)}`);
    }
    const challenge = ParseResponse(await response.json());
    if (!challenge) {
      throw new Error("invalid challenge response");
    }
    return challenge;
  }

  /** Programa el próximo Refresh, reemplazando el que hubiera pendiente. */
  private Schedule(delay: number): void {
    if (this.Cancellation.aborted) {
      return;
    }
    if (this.Timer !== null) {
      this.ClearTimer(this.Timer);
    }
    this.Timer = this.SetTimer(() => {
      this.Timer = null;
      void this.Refresh();
    }, delay);
  }
}
