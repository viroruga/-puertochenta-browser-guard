/**
 * Pesos por defecto de cada señal de riesgo.
 *
 * Los detectores emiten señales con nombre; RiskEngine suma sus pesos,
 * limita el resultado a 0-100 y lo traduce a severidad. Los pesos pueden
 * sobrescribirse desde la configuración (Risk.Weights).
 *
 * Referencia de umbrales: info < 20 ≤ low < 40 ≤ medium < 60 ≤ high < 80 ≤ critical.
 */
export const DefaultRiskWeights = {
  // Red
  "network.unknown-origin": 45,
  "network.blocked-origin": 90,
  "network.websocket": 10,
  "network.insecure-transport": 15,

  // Scripts y elementos del DOM
  "script.dynamic": 5,
  "script.external": 5,
  "script.inline": 25,
  "script.unknown-origin": 35,
  "script.missing-integrity": 20,
  "script.blocked-origin": 90,
  "script.dangerous-scheme": 60,
  "dom.embedded-content": 10,
  "dom.unknown-origin": 35,
  "dom.plugin-content": 20,
  "dom.blocked-origin": 90,

  // CSP
  "csp.violation": 35,
  "csp.script-directive": 20,
  "csp.report-only": -10,
  "csp.blocked-origin": 50,

  // Prototipos
  "prototype.added": 30,
  "prototype.removed": 25,
  "prototype.modified": 30,
  "prototype.suspicious-key": 40,
  "prototype.object-root": 15,
  "prototype.native-overridden": 25,

  // Integridad del runtime
  "runtime.modified": 45,
  "runtime.preexisting": 30,
  "runtime.removed": 40,
  "runtime.non-native": 20,
  "runtime.critical-target": 15,

  // Bots y scraping (alimentan además el veredicto de sesión de BotSession)
  "bot.webdriver": 80,
  "bot.headless": 70,
  "bot.automation-artifact": 80,
  "bot.env-software-gl": 25,
  "bot.env-no-languages": 20,
  "bot.env-zero-window": 20,
  "bot.env-ua-mismatch": 25,
  "bot.env-no-plugins": 10,
  "bot.request-burst": 35,
  "bot.sequential-crawl": 45,
  "bot.no-interaction": 30,
  "bot.synthetic-events": 30,
  "bot.human-interaction": -25,
} as const;

/**
 * Nombre de una señal de riesgo conocida.
 */
export type RiskSignal = keyof typeof DefaultRiskWeights;

/**
 * Tabla de pesos parcial, usada para sobrescribir los valores por defecto.
 */
export type RiskWeightOverrides = Partial<Record<RiskSignal, number>>;
