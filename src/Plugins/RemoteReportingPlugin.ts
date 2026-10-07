/**
 * Punto de entrada "@puertochenta/browser-guard/remote".
 *
 * El envío de hallazgos a un backend vive detrás de este módulo: quien no lo importe
 * no lo incluye en su bundle, y nada sale del navegador.
 */
import { ResolveRemoteConfig } from "../Config/ResolveRemoteConfig";
import { RemoteReporter } from "../Reporters/RemoteReporter";
import { RemoteTransport } from "../Reporters/RemoteTransport";
import type { RemoteConfig } from "../Types/BrowserGuardConfig";
import type { GuardPlugin } from "../Types/Plugin";

/**
 * Envío de hallazgos a tu endpoint, en lotes y con reintentos.
 *
 * ```ts
 * BrowserGuard.Start({
 *   Plugins: [RemoteReporting({ Endpoint: "https://security.example.com/findings" })],
 * });
 * ```
 *
 * Si el endpoint no es válido (debe ser https, del mismo origen o localhost), el plugin
 * queda inactivo y GetStatus().Plugins lo indica.
 */
export function RemoteReporting(config: RemoteConfig): GuardPlugin {
  return {
    Name: "RemoteReporting",
    Setup(host) {
      const settings = ResolveRemoteConfig(config);
      if (!settings) {
        return false;
      }
      // Setup se ejecuta antes de iniciar los monitores: el transporte captura el fetch
      // original y sus envíos nunca son interceptados (sin bucles).
      const window = host.Context.Window;
      const transport = new RemoteTransport(settings.Endpoint, settings.Headers, window);
      const reporter = new RemoteReporter(settings, transport, window, host.Context.SessionId);
      host.AddReporter(reporter);
      host.ProvideRemoteStats(() => reporter.GetStats());
      return true;
    },
  };
}

export type { RemoteConfig, RemoteMetadataValue } from "../Types/BrowserGuardConfig";
export type { RemotePayload, RemoteStats } from "../Types/Remote";
