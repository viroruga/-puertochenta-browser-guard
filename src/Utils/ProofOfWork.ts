/**
 * Prueba de trabajo compartida por el cliente (resuelve) y el servidor (verifica).
 *
 * Problema: dado un desafío, encontrar un número `n` tal que SHA-256("<desafío>:<n>")
 * comience con `difficulty` bits en cero. Resolverlo cuesta ~2^difficulty hashes;
 * verificarlo, uno solo.
 *
 * Usa Web Crypto (crypto.subtle), disponible en navegadores, Node 18+, Deno, Bun y
 * entornos edge, por lo que el mismo código sirve en ambos lados: lo usan
 * Protection/ChallengeClient (navegador) y Server/Challenge (backend).
 *
 * Una prueba válida demuestra que se gastó CPU, no que haya un humano: un navegador
 * automatizado la resuelve igual. Su valor es encarecer el scraping masivo y excluir a
 * clientes que no ejecutan JavaScript.
 */

/** Dificultad mínima aceptada, en bits (~256 hashes: trivial). */
export const MinDifficulty = 8;
/** Dificultad máxima aceptada, en bits (~16 millones de hashes: costosa en móviles). */
export const MaxDifficulty = 24;

/** Hashes calculados en paralelo por lote (amortiza el costo asíncrono de subtle). */
const BatchSize = 256;

const Encoder = new TextEncoder();

/** crypto.subtle o un error claro si el entorno no lo ofrece (p. ej. http no local). */
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
    // clz32 cuenta sobre 32 bits: se restan los 24 bits superiores, siempre en cero.
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

/**
 * Lleva una dificultad al rango [MinDifficulty, MaxDifficulty], redondeada. Valores no
 * finitos (NaN, Infinity) se tratan como la mínima.
 */
export function ClampDifficulty(difficulty: number): number {
  if (!Number.isFinite(difficulty)) {
    return MinDifficulty;
  }
  return Math.min(MaxDifficulty, Math.max(MinDifficulty, Math.round(difficulty)));
}

/** SHA-256 de "<desafío>:<nonce>". */
async function Hash(challenge: string, nonce: number): Promise<Uint8Array> {
  return new Uint8Array(await Subtle().digest("SHA-256", Encoder.encode(`${challenge}:${nonce}`)));
}

/**
 * Verifica una solución. Un solo hash. Rechaza nonces no enteros, negativos o fuera del
 * rango de enteros seguros: así `${nonce}` es exactamente el texto decimal que hasheó
 * el cliente (sin decimales ni notación exponencial).
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
 * `signal` permite cancelarlo (p. ej. al detener BrowserGuard); se consulta entre lotes.
 * Retorna el nonce menor que cumple la dificultad, o null si se canceló.
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

/**
 * Decodifica base64url sin relleno. Retorna null ante caracteres fuera del alfabeto o
 * una longitud imposible, en lugar de lanzar.
 */
export function FromBase64Url(text: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    return null;
  }
  try {
    // Restaura el relleno "=" que exige atob: (4 - len % 4) % 4 caracteres.
    const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

/** Texto a bytes UTF-8, con el tipo que aceptan las funciones de crypto.subtle. */
export function EncodeText(text: string): Uint8Array<ArrayBuffer> {
  return Encoder.encode(text);
}
