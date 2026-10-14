/**
 * Utilidades compartidas por los monitores de red (Fetch, Xhr, WebSocket, Channel,
 * Resource) para construir eventos `network.request` homogéneos. Esos eventos los
 * consumen NetworkDetector (origen de destino) y BotDetector (ráfagas y rastreo).
 *
 * Centralizar la construcción garantiza que todos apliquen el mismo saneamiento:
 * sin query string ni fragmento (solo su longitud), sin headers, cookies ni cuerpo.
 */
import type { GuardContext } from "../Core/GuardContext";
import type { NetworkRequestData, NetworkTransport } from "../Types/SecurityEvent";
import { DescribeUrl } from "../Utils/UrlUtils";

/**
 * Obtiene la URL de un argumento de red sin ejecutar código de la aplicación.
 *
 * Solo se aceptan strings, URL y Request. No se invoca String() sobre objetos
 * arbitrarios porque ejecutaría su toString() una vez más que la llamada original,
 * lo que podría alterar el comportamiento de la aplicación.
 *
 * Las comprobaciones usan los constructores del realm observado (`window`): un URL o
 * Request creado en otro realm no se reconoce y se informa como URL desconocida (null).
 */
export function ReadTargetUrl(input: unknown, window: Window & typeof globalThis): string | null {
  if (typeof input === "string") {
    return input;
  }
  if (input instanceof window.URL) {
    return input.href;
  }
  // Request puede no existir en entornos antiguos o simulados.
  if (typeof window.Request === "function" && input instanceof window.Request) {
    return input.url;
  }
  return null;
}

/**
 * Construye los datos normalizados de una solicitud de red.
 * Nunca incluye headers, cookies ni cuerpo; la URL se sanea (sin query ni fragmento) y de
 * la query solo se conserva la longitud. Si no se pudo leer la URL (null) se informa como
 * "[unknown]"; si no se puede parsear, DescribeUrl la informa como "[invalid-url]".
 */
export function CreateNetworkRequestData(
  context: GuardContext,
  transport: NetworkTransport,
  rawUrl: string | null,
  extras: { Method?: string; Protocols?: string[]; InitiatorType?: string } = {},
): NetworkRequestData {
  const described =
    rawUrl === null
      ? { Url: "[unknown]", Origin: null, HasQuery: false, QueryLength: 0 }
      : DescribeUrl(rawUrl, context.GetBaseUrl());

  const data: NetworkRequestData = {
    Transport: transport,
    Url: described.Url,
    Origin: described.Origin,
    HasQuery: described.HasQuery,
    QueryLength: described.QueryLength,
  };
  // Los campos opcionales solo se agregan si existen, para no ensuciar el evento serializado.
  if (extras.Method !== undefined) {
    // fetch/XHR aceptan el método en minúsculas; se normaliza para comparar.
    data.Method = extras.Method.toUpperCase();
  }
  if (extras.Protocols !== undefined) {
    data.Protocols = extras.Protocols;
  }
  if (extras.InitiatorType !== undefined) {
    data.InitiatorType = extras.InitiatorType;
  }
  return data;
}
