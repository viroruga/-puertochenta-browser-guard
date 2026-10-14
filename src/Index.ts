/**
 * API pública de la librería (entrada principal "@puertochenta/browser-guard").
 * Importar este módulo no tiene efectos secundarios: nada se intercepta hasta Start().
 *
 * Solo exporta la clase BrowserGuard y tipos. Las funciones opcionales viven en
 * entradas separadas para no cargarlas si no se usan: "/anti-scraping" y "/remote"
 * (plugins) y "/server" (verificación del desafío en el backend).
 */
export { BrowserGuard } from "./BrowserGuard";

export type {
  AntiScrapingConfig,
  BrowserGuardConfig,
  ConsoleMode,
  ConsoleNoticeText,
  GuardPreset,
  MonitorToggles,
  RemoteConfig,
  RemoteMetadataValue,
  ResolvedConfig,
} from "./Types/BrowserGuardConfig";
// Servicios de terceros conocidos que pueden declararse en la opción Services.
export type { KnownService } from "./Config/Services";
export type { Severity } from "./Types/Severity";
export type {
  FindingCategory,
  FindingStatistics,
  GuardReport,
  SecurityFinding,
} from "./Types/SecurityFinding";
export type {
  CspViolationData,
  DomElementData,
  NetworkRequestData,
  PrototypeChangeData,
  RuntimeModificationData,
  SecurityEvent,
  SecurityEventType,
} from "./Types/SecurityEvent";
export type {
  FindingEventName,
  FindingHandler,
  GuardEventHandler,
  GuardEventName,
  GuardSnapshot,
  GuardStatus,
} from "./Types/GuardStatus";
export type { BotAssessment, BotVerdict, ProofState } from "./Types/Bot";
export type { Monitor, MonitorStatus } from "./Types/Monitor";
export type { Reporter } from "./Reporters/Reporter";
export type { RemotePayload, RemoteStats } from "./Types/Remote";
export type { GuardPlugin, PluginHost, PluginStatus } from "./Types/Plugin";
// Para ajustar pesos con Risk.Weights e interpretar SecurityFinding.Signals.
export type { RiskSignal, RiskWeightOverrides } from "./Core/RiskSignals";
