import type { SecurityFinding } from "../Types/SecurityFinding";

/**
 * Contrato de un reporter: presenta o envía hallazgos ya evaluados.
 *
 * Por diseño, ningún reporter incluido envía datos fuera del navegador.
 * Un reporter remoto deberá ser configurado explícitamente por el desarrollador.
 */
export interface Reporter {
  readonly Name: string;
  Report(finding: SecurityFinding): void;
  /** Libera recursos (timers, cachés) al detener BrowserGuard. */
  Dispose?(): void;
}
