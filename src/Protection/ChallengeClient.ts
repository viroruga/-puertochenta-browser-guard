import type { ProofState } from "../Types/Bot";
import { ClampDifficulty, SolveWork } from "../Utils/ProofOfWork";

/** Renovar el desafío este tiempo antes de que venza. */
export const RefreshMarginMs = 60_000;
const MinRefreshDelayMs = 10_000;
const RetryDelaysMs: readonly number[] = [5_000, 30_000, 120_000, 300_000];

interface ChallengeResponse {
  Challenge: string;
  Difficulty: number;
  ExpiresAt: number;
}

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
 */
export class ChallengeClient {
  private readonly Fetch: typeof fetch | null;
  private readonly SetTimer: (callback: () => void, delay: number) => number;
  private readonly ClearTimer: (id: number) => void;
  private State: ProofState = "pending";
  private Proof: string | null = null;
  private ExpiresAt = 0;
  private Timer: number | null = null;
  private Failures = 0;
  private readonly Cancellation = { aborted: false };

  public constructor(
    private readonly Endpoint: string,
    private readonly SessionId: string,
    window: Window & typeof globalThis,
  ) {
    this.Fetch = typeof window.fetch === "function" ? window.fetch.bind(window) : null;
    this.SetTimer = window.setTimeout.bind(window) as (
      callback: () => void,
      delay: number,
    ) => number;
    this.ClearTimer = window.clearTimeout.bind(window);
  }

  public Start(): void {
    void this.Refresh();
  }

  public GetState(): ProofState {
    return this.State;
  }

  /** Prueba vigente, o null si aún no está lista o venció. */
  public GetProof(): string | null {
    return this.Proof !== null && Date.now() < this.ExpiresAt ? this.Proof : null;
  }

  public Dispose(): void {
    this.Cancellation.aborted = true;
    if (this.Timer !== null) {
      this.ClearTimer(this.Timer);
      this.Timer = null;
    }
  }

  private async Refresh(): Promise<void> {
    if (this.Cancellation.aborted) {
      return;
    }
    if (this.State !== "ready") {
      this.State = "pending";
    }
    try {
      const challenge = await this.Request();
      const nonce = await SolveWork(
        challenge.Challenge,
        ClampDifficulty(challenge.Difficulty),
        this.Cancellation,
      );
      if (nonce === null) {
        return;
      }
      this.Proof = `${challenge.Challenge}~${nonce}`;
      this.ExpiresAt = challenge.ExpiresAt;
      this.State = "ready";
      this.Failures = 0;
      this.Schedule(
        Math.max(MinRefreshDelayMs, challenge.ExpiresAt - Date.now() - RefreshMarginMs),
      );
    } catch {
      this.State = this.GetProof() !== null ? "ready" : "failed";
      const delay = RetryDelaysMs[Math.min(this.Failures, RetryDelaysMs.length - 1)] ?? 300_000;
      this.Failures++;
      this.Schedule(delay);
    }
  }

  private async Request(): Promise<ChallengeResponse> {
    if (!this.Fetch) {
      throw new Error("fetch is not available");
    }
    const separator = this.Endpoint.includes("?") ? "&" : "?";
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
