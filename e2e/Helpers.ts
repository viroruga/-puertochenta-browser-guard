import type { Page } from "@playwright/test";
import type { BrowserGuardConfig, SecurityFinding } from "../src/Index";
import type { AntiScrapingConfig } from "../src/Plugins/AntiScrapingPlugin";
import type { RemoteConfig } from "../src/Plugins/RemoteReportingPlugin";

/**
 * Configuración serializable de plugins: page.evaluate no puede transferir funciones,
 * por eso los plugins se construyen dentro de la página.
 */
export interface PluginOptions {
  AntiScraping?: AntiScrapingConfig;
  RemoteReporting?: RemoteConfig;
}

/** Origen alternativo: el navegador lo considera distinto de localhost. */
export const CrossOrigin = `http://127.0.0.1:${process.env.E2E_PORT ?? "4173"}`;

/** Monitores mínimos para aislar cada escenario. */
export const OnlyNetwork: BrowserGuardConfig["Monitors"] = {
  Dom: false,
  Csp: false,
  Prototype: false,
  Runtime: false,
};

/**
 * Abre una página de prueba y espera a que el bundle esté cargado.
 */
export async function OpenFixture(page: Page, path = "/fixtures/index.html"): Promise<void> {
  await page.goto(path);
  await page.waitForFunction(() => typeof window.BrowserGuard === "function");
}

/**
 * Inicia BrowserGuard en la página. La configuración debe ser serializable.
 */
export async function StartGuard(
  page: Page,
  config: Omit<BrowserGuardConfig, "Plugins">,
  plugins: PluginOptions = {},
): Promise<void> {
  await page.evaluate(
    ([options, pluginOptions]) => {
      const { AntiScraping, RemoteReporting } = window.Plugins;
      window.Guard = window.BrowserGuard.Start({
        ...options,
        Plugins: [
          ...(pluginOptions.AntiScraping ? [AntiScraping(pluginOptions.AntiScraping)] : []),
          ...(pluginOptions.RemoteReporting
            ? [RemoteReporting(pluginOptions.RemoteReporting)]
            : []),
        ],
      });
    },
    [config, plugins] as const,
  );
}

export async function Findings(page: Page): Promise<SecurityFinding[]> {
  return page.evaluate(() => window.Guard.GetReport().Findings);
}

export async function FindingTitles(page: Page): Promise<string[]> {
  return (await Findings(page)).map((finding) => finding.Title);
}
