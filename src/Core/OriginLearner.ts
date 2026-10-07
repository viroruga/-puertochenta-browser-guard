import type { BrowserGuardConfig, ResolvedConfig } from "../Types/BrowserGuardConfig";
import type { DomElementData, NetworkRequestData } from "../Types/SecurityEvent";
import { IsSameOrigin, MatchesAnyOrigin } from "../Utils/UrlUtils";

/** Orígenes distintos retenidos como máximo por lista (acota la memoria). */
export const MaxLearnedOrigins = 200;

/** Solo se aprenden orígenes de red reales (no data:, blob:, extensiones...). */
const LearnableOrigin = /^(https?|wss?):\/\/[^/]+$/i;

/**
 * Modo aprendizaje: acumula los orígenes de terceros observados que aún no están en
 * las listas permitidas, para proponer una configuración con GetLearnedConfig().
 *
 * - Nunca aprende orígenes bloqueados ni el propio origen.
 * - Registra orígenes exactos (sin comodines ni rutas): revisa la propuesta antes de
 *   adoptarla, porque un script malicioso presente durante el aprendizaje también
 *   quedaría listado.
 */
export class OriginLearner {
  private readonly Network = new Set<string>();
  private readonly Scripts = new Set<string>();

  public constructor(
    private readonly Config: ResolvedConfig,
    private readonly GetPageOrigin: () => string,
  ) {}

  public ObserveRequest(data: NetworkRequestData): void {
    this.Learn(this.Network, data.Origin, this.Config.Network.AllowedOrigins);
  }

  public ObserveElement(data: DomElementData): void {
    if (data.TagName === "script") {
      this.Learn(this.Scripts, data.Origin, this.Config.Dom.AllowedScriptOrigins);
    } else {
      this.Learn(this.Network, data.Origin, [
        ...this.Config.Network.AllowedOrigins,
        ...this.Config.Dom.AllowedScriptOrigins,
      ]);
    }
  }

  /**
   * Orígenes a agregar a la configuración actual (vacío si no se observó nada nuevo).
   */
  public GetLearnedConfig(): BrowserGuardConfig {
    return {
      Network: { AllowedOrigins: [...this.Network].sort() },
      Dom: { AllowedScriptOrigins: [...this.Scripts].sort() },
    };
  }

  private Learn(target: Set<string>, origin: string | null, allowed: readonly string[]): void {
    if (
      origin === null ||
      target.size >= MaxLearnedOrigins ||
      !LearnableOrigin.test(origin) ||
      IsSameOrigin(origin, this.GetPageOrigin()) ||
      MatchesAnyOrigin(origin, allowed) ||
      MatchesAnyOrigin(origin, this.Config.Network.BlockedOrigins)
    ) {
      return;
    }
    target.add(origin.toLowerCase());
  }
}
