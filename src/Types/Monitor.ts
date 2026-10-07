/**
 * Contrato común de todos los monitores.
 * Un monitor solo observa el runtime y genera eventos.
 */
export interface Monitor {
  readonly Name: string;
  Start(): void;
  Stop(): void;
  IsRunning(): boolean;
}

/**
 * Estado público de un monitor.
 */
export interface MonitorStatus {
  Name: string;
  Running: boolean;
}
