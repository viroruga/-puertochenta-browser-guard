/**
 * Generación de identificadores: de sesión (GuardContext, RemoteReporter) y de eventos y
 * hallazgos (GuardContext, RiskEngine).
 */

/** Contador del módulo: garantiza unicidad aunque Date.now() se repita. */
let Counter = 0;

/**
 * Identificador aleatorio de sesión (una por Start). No se persiste ni identifica
 * al usuario: solo agrupa los hallazgos y solicitudes de una carga de página.
 */
export function CreateSessionId(): string {
  // randomUUID solo existe en contextos seguros (https/localhost) y navegadores recientes.
  // El respaldo es predecible, pero el id no es un secreto: solo correlaciona.
  const crypto = (globalThis as { crypto?: Crypto }).crypto;
  return typeof crypto?.randomUUID === "function" ? crypto.randomUUID() : CreateId("session");
}

/**
 * Genera un identificador único y económico (sin criptografía), con la forma
 * "<prefijo>-<timestamp base36>-<contador base36>". Es predecible: solo sirve para
 * correlacionar, nunca como secreto.
 */
export function CreateId(prefix: string): string {
  Counter = (Counter + 1) % Number.MAX_SAFE_INTEGER;
  return `${prefix}-${Date.now().toString(36)}-${Counter.toString(36)}`;
}
