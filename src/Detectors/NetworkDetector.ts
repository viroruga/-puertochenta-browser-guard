import type { PageInfo } from "../Core/Components";
import type { RiskSignal } from "../Core/RiskSignals";
import type { ResolvedConfig } from "../Types/BrowserGuardConfig";
import type { Detector, FindingCandidate } from "../Types/Detector";
import type { NetworkRequestData, NetworkTransport, SecurityEvent } from "../Types/SecurityEvent";
import { ClassifyOrigin, IsInsecureTransport, ParseUrl } from "../Utils/UrlUtils";

/** Nombre legible de cada canal, para títulos y descripciones. */
const TransportLabels: Record<NetworkTransport, string> = {
  fetch: "fetch",
  xhr: "XMLHttpRequest",
  websocket: "WebSocket",
  beacon: "sendBeacon",
  eventsource: "EventSource",
  form: "form submission",
  "window-open": "window.open",
  resource: "resource load",
  "service-worker": "service worker registration",
};

/** Título del hallazgo cuando el destino es un origen desconocido, por canal. */
const UnknownTitles: Record<NetworkTransport, string> = {
  fetch: "Unknown outbound request",
  xhr: "Unknown outbound request",
  websocket: "WebSocket connection to unknown origin",
  beacon: "Beacon sent to unknown origin",
  eventsource: "Event stream from unknown origin",
  form: "Form submitted to unknown origin",
  "window-open": "Window opened to unknown origin",
  resource: "Resource loaded from unknown origin",
  "service-worker": "Service worker registered",
};

/**
 * Largo de query (en caracteres) a partir del cual se considera que transporta datos
 * (?c=<cookies>...). Por privacidad la URL llega sin query; el monitor solo informa su
 * largo (QueryLength).
 */
export const LargeQueryLength = 64;

/** Ventana durante la cual un hallazgo de red equivalente no se repite. */
export const NetworkDedupeWindowMs = 10_000;

/** Máximo de claves recordadas para deduplicar (memoria acotada). */
const MaxDedupeEntries = 300;

/**
 * Analiza la salida de datos por cualquier canal (fetch, XHR, WebSocket, sendBeacon,
 * EventSource, formularios, window.open, carga de recursos) comparando el origen de
 * destino contra AllowedOrigins y BlockedOrigins.
 *
 * Reglas:
 * - same-origin / AllowedOrigins: normal, sin hallazgo.
 * - origen externo desconocido: medium; un recurso pasivo (imagen, CSS) es low, porque
 *   cargar recursos de CDNs externos es habitual.
 * - query larga hacia un origen desconocido (patrón de exfiltración): suma riesgo.
 * - BlockedOrigins: critical.
 * - registro de un service worker: siempre low (da persistencia a quien lo controle).
 *
 * Consume "network.request" (FetchMonitor, XhrMonitor, WebSocketMonitor, ChannelMonitor,
 * ResourceMonitor). Los destinos sin origen de red (data:, blob:) no generan hallazgo.
 *
 * Los hallazgos equivalentes se agrupan durante NetworkDedupeWindowMs (p. ej. una
 * galería de imágenes de un mismo origen). Solo detecta y reporta; nunca bloquea.
 */
export class NetworkDetector implements Detector {
  public readonly Name = "NetworkDetector";
  public readonly Handles = ["network.request"] as const;
  /** Última vez (timestamp del evento) que se emitió cada clave de deduplicación. */
  private readonly Recent = new Map<string, number>();

  public constructor(
    private readonly Config: ResolvedConfig,
    private readonly Page: PageInfo,
  ) {}

  public Analyze(event: SecurityEvent): FindingCandidate | null {
    const data = event.Data as NetworkRequestData;
    const candidate =
      data.Transport === "service-worker"
        ? this.AnalyzeServiceWorker(data)
        : this.AnalyzeDestination(data);
    if (!candidate || this.IsDuplicate(data, candidate, event.Timestamp)) {
      return null;
    }
    return candidate;
  }

  /** Clasifica el destino y arma el hallazgo solo si es desconocido o bloqueado. */
  private AnalyzeDestination(data: NetworkRequestData): FindingCandidate | null {
    const classification = ClassifyOrigin(
      data.Origin,
      this.Page.GetPageOrigin(),
      this.Config.Network.AllowedOrigins,
      this.Config.Network.BlockedOrigins,
    );
    if (classification !== "unknown" && classification !== "blocked") {
      return null;
    }

    const transport = TransportLabels[data.Transport];
    const origin = data.Origin ?? "unknown";
    const signals: RiskSignal[] = [];
    let title: string;
    let description: string;

    if (classification === "blocked") {
      signals.push("network.blocked-origin");
      title = `Request to blocked origin via ${transport}`;
      description = `A ${transport} targeted ${origin}, which is listed in BlockedOrigins.`;
    } else {
      // Un recurso pasivo de un CDN externo es habitual: pesa menos que una solicitud
      // hecha por código, que puede llevar datos de la página.
      signals.push(
        data.Transport === "resource" ? "network.unknown-resource" : "network.unknown-origin",
      );
      title = UnknownTitles[data.Transport];
      description = `A ${transport} targeted ${origin}, which is not same-origin and not listed in AllowedOrigins.`;
    }

    if (data.Transport === "websocket") {
      signals.push("network.websocket");
    }
    if (data.QueryLength >= LargeQueryLength) {
      signals.push("network.large-query");
      description += ` The URL carries a large query string (${data.QueryLength} characters), a common exfiltration pattern.`;
    }

    // Solo cuenta como inseguro si degrada una página https (http:/ws: desde https:).
    const url = ParseUrl(data.Url);
    if (url && IsInsecureTransport(url, this.Page.GetPageProtocol())) {
      signals.push("network.insecure-transport");
      description += " The connection is not encrypted.";
    }

    return {
      Category: "network",
      Title: title,
      Description: description,
      Signals: signals,
      Evidence: this.Evidence(data, classification),
    };
  }

  /**
   * Todo registro de service worker se reporta, aunque sea del mismo origen: el script
   * queda instalado e intercepta las solicitudes del sitio incluso después de cerrar la
   * página, así que conviene que el equipo lo tenga a la vista.
   */
  private AnalyzeServiceWorker(data: NetworkRequestData): FindingCandidate {
    return {
      Category: "network",
      Title: UnknownTitles["service-worker"],
      Description: `A service worker was registered from ${data.Url}. Service workers intercept the site's requests and persist after the page closes.`,
      Signals: ["network.service-worker"],
      Evidence: this.Evidence(data, null),
    };
  }

  /**
   * Evidencia compacta: solo incluye los campos que aportan algo. La URL ya llega
   * sanitizada (sin query, fragmento ni credenciales).
   */
  private Evidence(
    data: NetworkRequestData,
    classification: string | null,
  ): Record<string, unknown> {
    const evidence: Record<string, unknown> = {
      Transport: data.Transport,
      Origin: data.Origin,
      Url: data.Url,
    };
    if (classification !== null) {
      evidence.Classification = classification;
    }
    if (data.Method !== undefined) {
      evidence.Method = data.Method;
    }
    if (data.Protocols !== undefined && data.Protocols.length > 0) {
      evidence.Protocols = data.Protocols;
    }
    if (data.QueryLength > 0) {
      evidence.QueryLength = data.QueryLength;
    }
    if (data.InitiatorType !== undefined) {
      evidence.InitiatorType = data.InitiatorType;
    }
    return evidence;
  }

  /**
   * Indica si un hallazgo equivalente (mismo canal, destino y señales) ya se emitió dentro
   * de NetworkDedupeWindowMs; si no, lo registra. Las señales forman parte de la clave para
   * que un cambio relevante (p. ej. aparece una query larga) sí se reporte.
   */
  private IsDuplicate(data: NetworkRequestData, candidate: FindingCandidate, now: number): boolean {
    const key = `${data.Transport}|${data.Origin ?? data.Url}|${candidate.Signals.join(",")}`;
    const last = this.Recent.get(key);
    if (last !== undefined && now - last < NetworkDedupeWindowMs) {
      return true;
    }
    // Reinsertar mantiene el orden por uso reciente para descartar las más antiguas.
    this.Recent.delete(key);
    this.Recent.set(key, now);
    if (this.Recent.size > MaxDedupeEntries) {
      const oldest = this.Recent.keys().next().value;
      if (oldest !== undefined) {
        this.Recent.delete(oldest);
      }
    }
    return false;
  }
}
