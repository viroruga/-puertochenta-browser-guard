let Counter = 0;

/**
 * Identificador aleatorio de sesión (una por Start). No se persiste ni identifica
 * al usuario: solo agrupa los hallazgos y solicitudes de una carga de página.
 */
export function CreateSessionId(): string {
  const crypto = (globalThis as { crypto?: Crypto }).crypto;
  return typeof crypto?.randomUUID === "function" ? crypto.randomUUID() : CreateId("session");
}

/**
 * Genera un identificador único y económico (sin criptografía).
 * Los identificadores solo se usan para correlación local.
 */
export function CreateId(prefix: string): string {
  Counter = (Counter + 1) % Number.MAX_SAFE_INTEGER;
  return `${prefix}-${Date.now().toString(36)}-${Counter.toString(36)}`;
}
