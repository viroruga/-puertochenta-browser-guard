import type { SecurityFinding } from "../Types/SecurityFinding";

/**
 * Contrato de un reporter: presenta o envía hallazgos ya evaluados.
 *
 * El núcleo solo incluye ConsoleReporter, que no envía datos fuera del navegador. El
 * envío a un endpoint (RemoteReporter) es opt-in: lo instala el plugin RemoteReporting
 * de "@puertochenta/browser-guard/remote". La aplicación puede sumar los suyos con
 * BrowserGuardConfig.Reporters.
 */
export interface Reporter {
  readonly Name: string;
  /**
   * Recibe cada hallazgo emitido. Se invoca de forma síncrona en el pipeline: debe ser
   * rápido y no lanzar (si lanza, el error se contabiliza y no afecta a otros reporters).
   */
  Report(finding: SecurityFinding): void;
  /** Libera recursos (timers, cachés) al detener BrowserGuard. */
  Dispose?(): void;
}
