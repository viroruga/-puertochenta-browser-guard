/**
 * Prueba de trabajo compartida por el cliente (resuelve) y el servidor (verifica).
 *
 * Problema: dado un desafío, encontrar un número `n` tal que SHA-256("<desafío>:<n>")
 * comience con `difficulty` bits en cero. Resolverlo cuesta ~2^difficulty hashes;
 * verificarlo, uno solo.
 *
 * Usa Web Crypto (crypto.subtle), disponible en navegadores, Node 18+, Deno, Bun y
 * entornos edge, por lo que el mismo código sirve en ambos lados.
 */

export const MinDifficulty = 8;
export const MaxDifficulty = 24;

/** Hashes calculados en paralelo por lote (amortiza el costo asíncrono de subtle). */
const BatchSize = 256;

const Encoder = new TextEncoder();

function Subtle(): SubtleCrypto {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) {
    throw new Error("Web Crypto (crypto.subtle) is not available");
  }
  return subtle;
}

/**
 * Cantidad de bits en cero al inicio de un hash.
 */
export function LeadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

export function ClampDifficulty(difficulty: number): number {
  if (!Number.isFinite(difficulty)) {
    return MinDifficulty;
  }
  return Math.min(MaxDifficulty, Math.max(MinDifficulty, Math.round(difficulty)));
}

async function Hash(challenge: string, nonce: number): Promise<Uint8Array> {
  return new Uint8Array(await Subtle().digest("SHA-256", Encoder.encode(`${challenge}:${nonce}`)));
}

/**
 * Verifica una solución. Un solo hash.
 */
export async function CheckWork(
  challenge: string,
  nonce: number,
  difficulty: number,
): Promise<boolean> {
  if (!Number.isSafeInteger(nonce) || nonce < 0) {
    return false;
  }
  return LeadingZeroBits(await Hash(challenge, nonce)) >= difficulty;
}

/**
 * Resuelve el desafío. Asíncrono y por lotes: no bloquea el hilo principal.
 * `signal` permite cancelarlo (p. ej. al detener BrowserGuard).
 */
export async function SolveWork(
  challenge: string,
  difficulty: number,
  signal?: { readonly aborted: boolean },
): Promise<number | null> {
  for (let start = 0; start < Number.MAX_SAFE_INTEGER; start += BatchSize) {
    if (signal?.aborted) {
      return null;
    }
    const hashes = await Promise.all(
      Array.from({ length: BatchSize }, (_, offset) => Hash(challenge, start + offset)),
    );
    const index = hashes.findIndex((hash) => LeadingZeroBits(hash) >= difficulty);
    if (index !== -1) {
      return start + index;
    }
  }
  return null;
}

/** Codificación base64url sin relleno (apta para headers y URLs). */
export function ToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function FromBase64Url(text: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    return null;
  }
  try {
    const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

export function EncodeText(text: string): Uint8Array<ArrayBuffer> {
  return Encoder.encode(text);
}
