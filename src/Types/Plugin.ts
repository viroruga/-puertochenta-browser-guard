import type { GuardContext } from "../Core/GuardContext";
import type { RiskEngine } from "../Core/RiskEngine";
import type { Reporter } from "../Reporters/Reporter";
import type { BotAssessment } from "./Bot";
import type { ResolvedConfig } from "./BrowserGuardConfig";
import type { Detector, FindingCandidate } from "./Detector";
import type { Monitor } from "./Monitor";
import type { RemoteStats } from "./Remote";

/**
 * Lo que BrowserGuard ofrece a un plugin durante Setup().
 *
 * Setup() se ejecuta antes de iniciar los monitores, por lo que un plugin puede
 * capturar referencias originales (p. ej. fetch) antes de que se intercepten.
 */
export interface PluginHost {
  readonly Config: ResolvedConfig;
  readonly Context: GuardContext;
  readonly Engine: RiskEngine;

  AddMonitor(monitor: Monitor): void;
  AddDetector(detector: Detector): void;
  AddReporter(reporter: Reporter): void;

  /** Recibe cada candidato producido por un detector, supere o no el umbral de reporte. */
  OnCandidate(listener: (candidate: FindingCandidate) => void): void;
  /** Se ejecuta en Stop(), después de procesar los eventos pendientes. */
  OnDispose(listener: () => void): void;

  /** Emite el evento público "Bot". */
  EmitBot(assessment: BotAssessment): void;
  /** Expone el veredicto en GetBotAssessment() y GetStatus().Bot. */
  ProvideBotAssessment(provider: () => BotAssessment): void;
  /** Expone los contadores en GetStatus().Remote. */
  ProvideRemoteStats(provider: () => RemoteStats): void;
}

/**
 * Plugin de BrowserGuard. Las funciones opcionales (anti-scraping, envío remoto) se
 * publican como plugins en rutas separadas del paquete, para que quien no las use no
 * las descargue.
 */
export interface GuardPlugin {
  readonly Name: string;
  /**
   * Instala el plugin. Retorna false si quedó inactivo (p. ej. configuración inválida);
   * GetStatus().Plugins lo refleja.
   */
  Setup(host: PluginHost): boolean;
}

/**
 * Estado público de un plugin.
 */
export interface PluginStatus {
  Name: string;
  Active: boolean;
}
