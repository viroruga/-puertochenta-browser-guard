/**
 * Punto de entrada "@puertochenta/browser-guard/anti-scraping".
 *
 * Todo el código de detección de bots vive detrás de este módulo: quien no lo importe
 * no lo incluye en su bundle.
 */
import { ResolveAntiScrapingConfig } from "../Config/ResolveAntiScrapingConfig";
import { AntiScrapingController } from "../Core/AntiScrapingController";
import { BotDetector } from "../Detectors/BotDetector";
import { AutomationMonitor } from "../Monitors/AutomationMonitor";
import { InteractionMonitor } from "../Monitors/InteractionMonitor";
import type { AntiScrapingConfig } from "../Types/BrowserGuardConfig";
import type { GuardPlugin } from "../Types/Plugin";

/**
 * Detección de navegadores automatizados y comportamiento de scraping.
 *
 * Al instalarse (Setup) registra en el PluginHost:
 * - AntiScrapingController: veredicto de sesión (BotSession), ContentShield, header de
 *   veredicto y, si se configuró Challenge, el ChallengeClient;
 * - AutomationMonitor e InteractionMonitor, según las señales habilitadas;
 * - BotDetector, que convierte esos eventos (y las solicitudes de red) en hallazgos.
 *
 * Si la configuración tiene Enabled: false, Setup retorna false y el plugin queda
 * inactivo (GetStatus().Plugins lo indica).
 *
 * ```ts
 * BrowserGuard.Start({ Plugins: [AntiScraping({ ProtectAt: "bot" })] });
 * ```
 */
export function AntiScraping(config: AntiScrapingConfig = {}): GuardPlugin {
  return {
    Name: "AntiScraping",
    Setup(host) {
      const settings = ResolveAntiScrapingConfig(config);
      if (!settings) {
        return false;
      }
      // Antes que los monitores: el header de veredicto debe estar disponible desde la
      // primera solicitud interceptada.
      const controller = new AntiScrapingController(
        settings,
        host.Engine,
        host.Context,
        (assessment) => {
          host.EmitBot(assessment);
        },
      );
      // Expone el veredicto en GetBotAssessment() y GetStatus().Bot.
      host.ProvideBotAssessment(() => controller.GetAssessment());
      host.OnCandidate((candidate) => {
        // El veredicto usa todas las señales de bot, aunque el hallazgo no supere el umbral.
        if (candidate.Category === "bot") {
          controller.Observe(candidate.Signals);
        }
      });
      host.OnDispose(() => {
        controller.Dispose();
      });

      // RequestRate no necesita monitor propio: BotDetector usa los eventos de red que ya
      // emiten los monitores del núcleo.
      const { Automation, Environment, Interaction } = settings.Signals;
      if (Automation || Environment) {
        host.AddMonitor(new AutomationMonitor(host.Context, settings));
      }
      if (Interaction) {
        host.AddMonitor(new InteractionMonitor(host.Context));
      }
      host.AddDetector(new BotDetector(settings));
      return true;
    },
  };
}

// Tipos públicos re-exportados para que este subpath sea autosuficiente.
export type { AntiScrapingConfig } from "../Types/BrowserGuardConfig";
export type { BotAssessment, BotVerdict, ProofState } from "../Types/Bot";
