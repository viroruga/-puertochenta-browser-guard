import type { BotAssessment } from "./Bot";
import type { GuardPreset } from "./BrowserGuardConfig";
import type { RemoteStats } from "./Remote";
import type { MonitorStatus } from "./Monitor";
import type { PluginStatus } from "./Plugin";
import type { SecurityFinding } from "./SecurityFinding";

/**
 * Eventos públicos a los que puede suscribirse la aplicación.
 *
 * - Finding: todo hallazgo que supera el umbral configurado.
 * - Threat: hallazgos con severidad low o superior (excluye los informativos).
 * - Critical / High / Medium / Low / Info: hallazgos de esa severidad exacta.
 * - Bot: cambio del veredicto anti-scraping de la sesión (recibe un BotAssessment).
 */
export type FindingEventName =
  "Threat" | "Finding" | "Critical" | "High" | "Medium" | "Low" | "Info";

export type GuardEventName = FindingEventName | "Bot";

export type FindingHandler = (finding: SecurityFinding) => void;

export type PublicEventMap = Record<FindingEventName, SecurityFinding> & { Bot: BotAssessment };

/** Manejador tipado según el evento. */
export type GuardEventHandler<K extends GuardEventName> = (payload: PublicEventMap[K]) => void;

/**
 * Estado operativo de BrowserGuard.
 */
export interface GuardStatus {
  /** El entorno tiene window/document (no SSR). */
  Supported: boolean;
  Running: boolean;
  Preset: GuardPreset;
  StartedAt: number;
  StoppedAt: number | null;
  Monitors: MonitorStatus[];
  FindingsCount: number;
  TimelineSize: number;
  DroppedEvents: number;
  InternalErrors: number;
  /** Plugins registrados y si quedaron activos. */
  Plugins: PluginStatus[];
  /** Contadores del plugin RemoteReporting, o null si no está activo. */
  Remote: RemoteStats | null;
  /** Veredicto del plugin AntiScraping, o null si no está activo. */
  Bot: BotAssessment | null;
  /** Id aleatorio de la sesión (el mismo del envío remoto y del header de veredicto). */
  SessionId: string | null;
}
