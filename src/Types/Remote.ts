import type { RemoteMetadataValue } from "./BrowserGuardConfig";
import type { SecurityFinding } from "./SecurityFinding";

/** Identificador del formato del payload, para versionarlo en el backend. */
export type RemotePayloadSchemaName = "browser-guard.findings/v1";

/**
 * Cuerpo enviado al endpoint por el plugin RemoteReporting.
 */
export interface RemotePayload {
  Schema: RemotePayloadSchemaName;
  SentAt: number;
  /** Aleatorio por cada Start(): correlaciona hallazgos de una misma carga de página. */
  SessionId: string;
  Page: { Origin: string; Path?: string };
  Metadata?: Record<string, RemoteMetadataValue>;
  Findings: Partial<SecurityFinding>[];
}

/**
 * Contadores del envío remoto, expuestos en GetStatus().Remote.
 */
export interface RemoteStats {
  Queued: number;
  Sent: number;
  /** Descartados antes de enviarse (cola llena o hallazgo demasiado grande). */
  Dropped: number;
  /** Descartados después de agotar los reintentos o por error no recuperable. */
  Failed: number;
}
