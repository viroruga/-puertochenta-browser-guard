import type { PageInfo } from "../Core/Components";
import type { RiskSignal } from "../Core/RiskSignals";
import type { ResolvedConfig } from "../Types/BrowserGuardConfig";
import type { Detector, FindingCandidate } from "../Types/Detector";
import type { NetworkRequestData, SecurityEvent } from "../Types/SecurityEvent";
import { ClassifyOrigin, IsInsecureTransport, ParseUrl } from "../Utils/UrlUtils";

const TransportLabels: Record<NetworkRequestData["Transport"], string> = {
  fetch: "fetch",
  xhr: "XMLHttpRequest",
  websocket: "WebSocket",
};

/**
 * Analiza solicitudes salientes (fetch, XHR, WebSocket) comparando el origen
 * de destino contra AllowedOrigins y BlockedOrigins.
 *
 * Reglas:
 * - same-origin / AllowedOrigins: normal, sin hallazgo.
 * - origen externo desconocido: medium (más alto si es WebSocket o degrada a HTTP).
 * - BlockedOrigins: critical.
 *
 * Solo detecta y reporta; nunca bloquea la solicitud.
 */
export class NetworkDetector implements Detector {
  public readonly Name = "NetworkDetector";
  public readonly Handles = ["network.request"] as const;

  public constructor(
    private readonly Config: ResolvedConfig,
    private readonly Page: PageInfo,
  ) {}

  public Analyze(event: SecurityEvent): FindingCandidate | null {
    const data = event.Data as NetworkRequestData;
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
      description = `A ${transport} request targeted ${origin}, which is listed in BlockedOrigins.`;
    } else {
      signals.push("network.unknown-origin");
      title =
        data.Transport === "websocket"
          ? "WebSocket connection to unknown origin"
          : "Unknown outbound request";
      description = `A ${transport} request targeted ${origin}, which is not same-origin and not listed in AllowedOrigins.`;
    }

    if (data.Transport === "websocket") {
      signals.push("network.websocket");
    }

    const url = ParseUrl(data.Url);
    if (url && IsInsecureTransport(url, this.Page.GetPageProtocol())) {
      signals.push("network.insecure-transport");
      description += " The connection is not encrypted.";
    }

    const evidence: Record<string, unknown> = {
      Transport: data.Transport,
      Origin: data.Origin,
      Url: data.Url,
      Classification: classification,
    };
    if (data.Method !== undefined) {
      evidence.Method = data.Method;
    }
    if (data.Protocols !== undefined && data.Protocols.length > 0) {
      evidence.Protocols = data.Protocols;
    }

    return {
      Category: "network",
      Title: title,
      Description: description,
      Signals: signals,
      Evidence: evidence,
    };
  }
}
