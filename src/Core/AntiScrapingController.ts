import { ChallengeClient } from "../Protection/ChallengeClient";
import { ContentShield } from "../Protection/ContentShield";
import type { BotAssessment, BotVerdict, SessionAssessment } from "../Types/Bot";
import type { ResolvedAntiScrapingConfig } from "../Types/BrowserGuardConfig";
import { GetOrigin, IsSameOrigin, MatchesAnyOrigin, ParseUrl } from "../Utils/UrlUtils";
import { BotSession } from "./BotSession";
import type { GuardContext } from "./GuardContext";
import type { RiskEngine } from "./RiskEngine";
import type { RiskSignal } from "./RiskSignals";

/**
 * Orden de gravedad de los veredictos, para comparar con Settings.ProtectAt.
 * "unknown" y "human" comparten rango: ninguno debe activar la protección.
 */
const VerdictRank: Record<BotVerdict, number> = { unknown: 0, human: 0, suspicious: 1, bot: 2 };

/**
 * Núcleo del plugin AntiScraping (lo crea AntiScrapingPlugin en su Setup). Recibe las
 * señales de bot por PluginHost.OnCandidate y orquesta las reacciones anti-scraping:
 * - mantiene el veredicto de sesión (BotSession);
 * - retira el contenido protegido al alcanzar el veredicto configurado (ContentShield);
 * - provee el header de veredicto para las solicitudes salientes, con la prueba de
 *   trabajo del desafío del servidor si se configuró (ChallengeClient).
 *
 * La protección de contenido es persistente: una vez activada, se mantiene hasta Stop().
 *
 * BrowserGuard sigue siendo "detectar y reportar": el controlador no bloquea solicitudes
 * ni navegación; solo oculta el contenido marcado por la aplicación y le informa el
 * veredicto al servidor, que es quien decide.
 */
export class AntiScrapingController {
  private readonly Session: BotSession;
  private readonly Shield: ContentShield;
  private readonly Challenge: ChallengeClient | null;

  /**
   * @param Settings Configuración AntiScraping resuelta.
   * @param engine Motor de riesgo, para puntuar la sesión con los pesos configurados.
   * @param Context Contexto de la sesión (window, id de sesión, header de solicitudes).
   * @param onVerdict Se invoca cuando cambia el veredicto o el estado de la prueba.
   */
  public constructor(
    private readonly Settings: ResolvedAntiScrapingConfig,
    engine: RiskEngine,
    private readonly Context: GuardContext,
    onVerdict: (assessment: BotAssessment) => void,
  ) {
    this.Shield = new ContentShield(Context.Window, Settings.ProtectSelector, Settings.Placeholder);
    this.Session = new BotSession(engine, (assessment) => {
      // Proteger antes de notificar: la aplicación ve el veredicto con el contenido ya retirado.
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

  /** Veredicto actual de la sesión con el estado de la prueba del desafío. */
  public GetAssessment(): BotAssessment {
    return this.WithProof(this.Session.Get());
  }

  /** Indica si el contenido protegido ya fue retirado. */
  public IsShieldActive(): boolean {
    return this.Shield.IsActive();
  }

  /** Repone el contenido protegido, deja de agregar el header y detiene el desafío. */
  public Dispose(): void {
    this.Challenge?.Dispose();
    this.Context.SetRequestHeaderProvider(null);
    this.Context.Safely(() => {
      this.Shield.Restore();
    });
  }

  /** Completa la evaluación de sesión con el estado de la prueba ("disabled" sin desafío). */
  private WithProof(assessment: SessionAssessment): BotAssessment {
    return { ...assessment, Proof: this.Challenge?.GetState() ?? "disabled" };
  }

  /** Retira el contenido protegido si el veredicto alcanza Settings.ProtectAt. */
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
   *
   * Nunca se envía a otros orígenes no configurados: el header expone el id de sesión y
   * el veredicto, que no deben filtrarse a terceros (ni provocar preflights CORS ajenos).
   */
  private HeaderFor(rawUrl: string | null): readonly [string, string] | null {
    if (rawUrl === null) {
      return null;
    }
    // Las URLs relativas se resuelven contra la base del documento (respeta <base href>).
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
