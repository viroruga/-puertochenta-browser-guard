import { ChallengeClient } from "../Protection/ChallengeClient";
import { ContentShield } from "../Protection/ContentShield";
import type { BotAssessment, BotVerdict, SessionAssessment } from "../Types/Bot";
import type { ResolvedAntiScrapingConfig } from "../Types/BrowserGuardConfig";
import { GetOrigin, IsSameOrigin, MatchesAnyOrigin, ParseUrl } from "../Utils/UrlUtils";
import { BotSession } from "./BotSession";
import type { GuardContext } from "./GuardContext";
import type { RiskEngine } from "./RiskEngine";
import type { RiskSignal } from "./RiskSignals";

const VerdictRank: Record<BotVerdict, number> = { unknown: 0, human: 0, suspicious: 1, bot: 2 };

/**
 * Orquesta las reacciones anti-scraping:
 * - mantiene el veredicto de sesión (BotSession);
 * - retira el contenido protegido al alcanzar el veredicto configurado (ContentShield);
 * - provee el header de veredicto para las solicitudes salientes, con la prueba de
 *   trabajo del desafío del servidor si se configuró (ChallengeClient).
 *
 * La protección de contenido es persistente: una vez activada, se mantiene hasta Stop().
 */
export class AntiScrapingController {
  private readonly Session: BotSession;
  private readonly Shield: ContentShield;
  private readonly Challenge: ChallengeClient | null;

  public constructor(
    private readonly Settings: ResolvedAntiScrapingConfig,
    engine: RiskEngine,
    private readonly Context: GuardContext,
    onVerdict: (assessment: BotAssessment) => void,
  ) {
    this.Shield = new ContentShield(Context.Window, Settings.ProtectSelector, Settings.Placeholder);
    this.Session = new BotSession(engine, (assessment) => {
      this.ApplyProtection(assessment);
      onVerdict(this.WithProof(assessment));
    });
    // Se crea durante Setup, antes de interceptar fetch: sus solicitudes no se observan.
    this.Challenge = Settings.Challenge
      ? new ChallengeClient(Settings.Challenge.Endpoint, Context.SessionId, Context.Window, () => {
          // El estado de la prueba forma parte del veredicto publicado.
          onVerdict(this.GetAssessment());
        })
      : null;
    this.Challenge?.Start();
    if (Settings.VerdictHeader.Enabled) {
      Context.SetRequestHeaderProvider((url) => this.HeaderFor(url));
    }
  }

  /** Incorpora señales de un hallazgo de categoría "bot". */
  public Observe(signals: readonly RiskSignal[]): void {
    this.Session.Add(signals);
  }

  public GetAssessment(): BotAssessment {
    return this.WithProof(this.Session.Get());
  }

  public IsShieldActive(): boolean {
    return this.Shield.IsActive();
  }

  /** Repone el contenido protegido y deja de agregar el header. */
  public Dispose(): void {
    this.Challenge?.Dispose();
    this.Context.SetRequestHeaderProvider(null);
    this.Context.Safely(() => {
      this.Shield.Restore();
    });
  }

  private WithProof(assessment: SessionAssessment): BotAssessment {
    return { ...assessment, Proof: this.Challenge?.GetState() ?? "disabled" };
  }

  private ApplyProtection(assessment: SessionAssessment): void {
    if (VerdictRank[assessment.Verdict] >= VerdictRank[this.Settings.ProtectAt]) {
      this.Context.Safely(() => {
        this.Shield.Activate();
      });
    }
  }

  /**
   * Header para solicitudes al propio origen o a los orígenes configurados.
   * Formato: "<veredicto>; score=<0-100>; sid=<id de sesión>[; proof=<desafío>~<solución>]".
   */
  private HeaderFor(rawUrl: string | null): readonly [string, string] | null {
    if (rawUrl === null) {
      return null;
    }
    const url = ParseUrl(rawUrl, this.Context.GetBaseUrl());
    const origin = url ? GetOrigin(url) : null;
    if (
      origin === null ||
      (!IsSameOrigin(origin, this.Context.GetPageOrigin()) &&
        !MatchesAnyOrigin(origin, this.Settings.VerdictHeader.Origins))
    ) {
      return null;
    }
    const assessment = this.Session.Get();
    const proof = this.Challenge?.GetProof();
    return [
      this.Settings.VerdictHeader.Name,
      `${assessment.Verdict}; score=${assessment.Score}; sid=${this.Context.SessionId}` +
        (proof ? `; proof=${proof}` : ""),
    ];
  }
}
