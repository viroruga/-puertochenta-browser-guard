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
 * BrowserGuard lo crea solo con Learning.Enabled y le pasa, antes que a los detectores,
 * los eventos "network.request" y "dom.element-inserted". No genera hallazgos ni altera
 * la detección: la configuración en uso no cambia hasta que la aplicación la adopte.
 * Solo retiene orígenes (esquema + host + puerto), nunca rutas, parámetros ni contenido.
 *
 * - Nunca aprende orígenes bloqueados ni el propio origen.
 * - Registra orígenes exactos (sin comodines ni rutas): revisa la propuesta antes de
 *   adoptarla, porque un script malicioso presente durante el aprendizaje también
 *   quedaría listado.
 */
export class OriginLearner {
  private readonly Network = new Set<string>();
  private readonly Scripts = new Set<string>();

  /**
   * @param Config Configuración en uso: sus listas definen qué ya está permitido o bloqueado.
   * @param GetPageOrigin Origen de la página, consultado en cada observación.
   */
  public constructor(
    private readonly Config: ResolvedConfig,
    private readonly GetPageOrigin: () => string,
  ) {}

  /** Considera el origen de destino de una solicitud de red (fetch, XHR, WebSocket...). */
  public ObserveRequest(data: NetworkRequestData): void {
    this.Learn(this.Network, data.Origin, this.Config.Network.AllowedOrigins);
  }

  /**
   * Considera el origen de un elemento insertado en el DOM. Los scripts van a
   * Dom.AllowedScriptOrigins; el resto (iframe, object, embed) a Network.AllowedOrigins.
   */
  public ObserveElement(data: DomElementData): void {
    if (data.TagName === "script") {
      this.Learn(this.Scripts, data.Origin, this.Config.Dom.AllowedScriptOrigins);
    } else {
      // Un origen ya permitido para scripts tampoco se propone para recursos.
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

  /** Agrega el origen a la lista si es aprendible, nuevo para la configuración y hay cupo. */
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
    // Normalizado para no duplicar el mismo origen escrito con mayúsculas distintas.
    target.add(origin.toLowerCase());
  }
}
