/**
 * API pública de la librería.
 * Importar este módulo no tiene efectos secundarios: nada se intercepta hasta Start().
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
export type { RiskSignal, RiskWeightOverrides } from "./Core/RiskSignals";
