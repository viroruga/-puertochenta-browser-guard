/**
 * Contrato común de todos los monitores.
 * Un monitor solo observa el runtime y genera eventos (SecurityEvent); nunca decide si
 * algo es un ataque ni bloquea a la aplicación.
 */
export interface Monitor {
  readonly Name: string;
  /** Instala la observación (wrappers, observers, listeners). Idempotente. */
  Start(): void;
  /** Deshace lo instalado en Start(), en la medida de lo posible. */
  Stop(): void;
  IsRunning(): boolean;
}

/**
 * Estado público de un monitor (GetStatus().Monitors).
 */
export interface MonitorStatus {
  Name: string;
  Running: boolean;
}
