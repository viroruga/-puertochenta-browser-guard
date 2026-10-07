import type { GuardContext } from "../Core/GuardContext";
import type { NetworkRequestData, NetworkTransport } from "../Types/SecurityEvent";
import { DescribeUrl } from "../Utils/UrlUtils";

/**
 * Obtiene la URL de un argumento de red sin ejecutar código de la aplicación.
 *
 * Solo se aceptan strings, URL y Request. No se invoca String() sobre objetos
 * arbitrarios porque ejecutaría su toString() una vez más que la llamada original,
 * lo que podría alterar el comportamiento de la aplicación.
 */
export function ReadTargetUrl(input: unknown, window: Window & typeof globalThis): string | null {
  if (typeof input === "string") {
    return input;
  }
  if (input instanceof window.URL) {
    return input.href;
  }
  if (typeof window.Request === "function" && input instanceof window.Request) {
    return input.url;
  }
  return null;
}

/**
 * Construye los datos normalizados de una solicitud de red.
 * Nunca incluye headers, cookies ni cuerpo; la URL se sanea (sin query ni fragmento).
 */
export function CreateNetworkRequestData(
  context: GuardContext,
  transport: NetworkTransport,
  rawUrl: string | null,
  extras: { Method?: string; Protocols?: string[] } = {},
): NetworkRequestData {
  const described =
    rawUrl === null
      ? { Url: "[unknown]", Origin: null, HasQuery: false }
      : DescribeUrl(rawUrl, context.GetBaseUrl());

  const data: NetworkRequestData = {
    Transport: transport,
    Url: described.Url,
    Origin: described.Origin,
    HasQuery: described.HasQuery,
  };
  if (extras.Method !== undefined) {
    data.Method = extras.Method.toUpperCase();
  }
  if (extras.Protocols !== undefined) {
    data.Protocols = extras.Protocols;
  }
  return data;
}
