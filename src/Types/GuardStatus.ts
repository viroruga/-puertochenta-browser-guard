import type { BotAssessment } from "./Bot";
import type { GuardPreset } from "./BrowserGuardConfig";
import type { RemoteStats } from "./Remote";
import type { MonitorStatus } from "./Monitor";
import type { PluginStatus } from "./Plugin";
import type { FindingStatistics, SecurityFinding } from "./SecurityFinding";

/**
 * Tipos públicos del estado y los eventos de BrowserGuard: nombres de evento y sus
 * payloads (On/Off), snapshot del store reactivo (Subscribe/GetSnapshot) y GetStatus().
 */

/**
 * Eventos públicos de hallazgos a los que puede suscribirse la aplicación.
 *
 * - Finding: todo hallazgo que supera el umbral configurado.
 * - Threat: hallazgos con severidad low o superior (excluye los informativos).
 * - Critical / High / Medium / Low / Info: hallazgos de esa severidad exacta.
 *
 * El evento "Bot" (ver GuardEventName) no es de hallazgos: recibe un BotAssessment.
 */
export type FindingEventName =
  "Threat" | "Finding" | "Critical" | "High" | "Medium" | "Low" | "Info";

/**
 * Todos los eventos públicos: los de hallazgos más "Bot" (cambio del veredicto
 * anti-scraping de la sesión; solo con el plugin AntiScraping).
 */
export type GuardEventName = FindingEventName | "Bot";

/** Manejador de los eventos de hallazgos. */
export type FindingHandler = (finding: SecurityFinding) => void;

/** Payload de cada evento público. */
export type PublicEventMap = Record<FindingEventName, SecurityFinding> & { Bot: BotAssessment };

/** Manejador tipado según el evento. */
export type GuardEventHandler<K extends GuardEventName> = (payload: PublicEventMap[K]) => void;

/**
 * Snapshot inmutable para frameworks (ver Guard.Subscribe / Guard.GetSnapshot).
 */
export interface GuardSnapshot {
  /** BrowserGuard está iniciado. */
  Running: boolean;
  /** Veredicto anti-scraping, o null sin el plugin AntiScraping. */
  Bot: BotAssessment | null;
  /** Último hallazgo emitido, o null. */
  LastFinding: SecurityFinding | null;
  /** Estadísticas acumuladas desde Start(). */
  Statistics: FindingStatistics;
}

/**
 * Estado operativo de BrowserGuard.
 */
export interface GuardStatus {
  /** El entorno tiene window/document (no SSR). */
  Supported: boolean;
  Running: boolean;
  Preset: GuardPreset;
  /** Creación de la instancia (Start()), en ms desde epoch. */
  StartedAt: number;
  /** Momento de Stop(), o null si sigue activo. */
  StoppedAt: number | null;
  Monitors: MonitorStatus[];
  /** Hallazgos conservados en el historial (acotado por History.MaxFindings). */
  FindingsCount: number;
  /** Eventos en la línea de tiempo forense (0 si Forensic no está habilitado). */
  TimelineSize: number;
  /**
   * Eventos descartados por saturación de la cola interna. Un valor alto puede indicar
   * un script que intenta inundar el pipeline para ocultar actividad.
   */
  DroppedEvents: number;
  /**
   * Errores internos contenidos (monitores, detectores, reporters, plugins). Nunca se
   * propagan a la aplicación; solo se cuentan.
   */
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
