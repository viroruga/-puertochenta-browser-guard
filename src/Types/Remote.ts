import type { RemoteMetadataValue } from "./BrowserGuardConfig";
import type { SecurityFinding } from "./SecurityFinding";

/**
 * Tipos del envío remoto (plugin RemoteReporting): formato del cuerpo que recibe el
 * endpoint del propietario y contadores expuestos en GetStatus().Remote.
 */

/** Identificador del formato del payload, para versionarlo en el backend. */
export type RemotePayloadSchemaName = "browser-guard.findings/v1";

/**
 * Cuerpo enviado al endpoint por el plugin RemoteReporting.
 */
export interface RemotePayload {
  Schema: RemotePayloadSchemaName;
  /** Momento de armado del lote, en ms desde epoch (reloj del cliente). */
  SentAt: number;
  /** Aleatorio por cada Start(): correlaciona hallazgos de una misma carga de página. */
  SessionId: string;
  /** Página emisora. Path (sin query ni fragmento) solo con IncludePagePath. */
  Page: { Origin: string; Path?: string };
  /** RemoteConfig.Metadata; se omite si está vacío. */
  Metadata?: Record<string, RemoteMetadataValue>;
  /**
   * Hallazgos del lote. Parciales: Evidence y Stack pueden faltar por configuración
   * (IncludeEvidence/IncludeStack) o por exceder el límite de tamaño del payload.
   */
  Findings: Partial<SecurityFinding>[];
}

/**
 * Contadores del envío remoto, expuestos en GetStatus().Remote.
 */
export interface RemoteStats {
  /** Hallazgos en cola, pendientes de envío. */
  Queued: number;
  /** Hallazgos enviados con éxito (al cerrar la página: aceptados por el navegador). */
  Sent: number;
  /** Descartados antes de enviarse (cola llena o hallazgo demasiado grande). */
  Dropped: number;
  /** Descartados después de agotar los reintentos o por error no recuperable. */
  Failed: number;
}
