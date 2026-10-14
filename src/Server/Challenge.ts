/**
 * Verificación en el servidor del header de veredicto anti-scraping.
 *
 * Flujo:
 * 1. El servidor emite un desafío firmado (CreateChallenge), atado a la sesión y con
 *    vencimiento. El secreto nunca sale del servidor.
 * 2. El navegador resuelve una prueba de trabajo sobre el desafío y la envía en el header
 *    X-BrowserGuard-Verdict (`...; proof=<desafío>~<solución>`).
 * 3. El servidor verifica firma, vencimiento, sesión y trabajo (VerifyRequest).
 *
 * Qué garantiza: que el cliente obtuvo un desafío de este servidor y gastó CPU para
 * resolverlo. Un cliente sin JavaScript (curl, requests, Scrapy) no puede fabricar el
 * header. Qué NO garantiza: que el cliente sea humano; un navegador automatizado puede
 * resolverlo. El veredicto (human/bot) sigue siendo una declaración del cliente.
 *
 * Tampoco es de un solo uso: una prueba válida puede repetirse hasta su vencimiento
 * (no se guarda estado en el servidor). El TTL acota esa ventana; quien necesite
 * evitar la reutilización debe registrar los desafíos ya usados.
 *
 * Solo usa Web Crypto: funciona en Node 18+, Deno, Bun y entornos edge.
 */
import {
  CheckWork,
  ClampDifficulty,
  EncodeText,
  FromBase64Url,
  ToBase64Url,
} from "../Utils/ProofOfWork";

/** Longitud mínima del secreto (debe ser aleatorio y privado). */
export const MinSecretLength = 32;

/** Dificultad por defecto, en bits (~16 mil hashes en promedio para resolverla). */
export const DefaultDifficulty = 14;
/** Vigencia por defecto de un desafío, en segundos (10 minutos). */
export const DefaultTtlSeconds = 600;

/** Opciones de CreateChallenge (y, en parte, de VerifyProof). */
export interface ChallengeOptions {
  /** Secreto HMAC del servidor (mínimo 32 caracteres). Nunca se envía al cliente. */
  Secret: string;
  /** Bits en cero exigidos (8-24). Cada bit duplica el trabajo. Por defecto: 14. */
  Difficulty?: number;
  /** Vigencia del desafío, en segundos (mínimo 30). Por defecto: 600. */
  TtlSeconds?: number;
  /** Ata el desafío a una sesión de BrowserGuard (parámetro `sid` de la solicitud). */
  SessionId?: string | null;
  /** Instante actual en ms desde epoch, en lugar de Date.now() (para tests). */
  Now?: number;
}

/** Desafío emitido; el endpoint lo devuelve como JSON al navegador. */
export interface IssuedChallenge {
  /** "<payload base64url>.<firma HMAC base64url>". Opaco para el cliente. */
  Challenge: string;
  /** Dificultad efectiva (ya acotada a 8-24). */
  Difficulty: number;
  /** Vencimiento en ms desde epoch. */
  ExpiresAt: number;
}

/**
 * Resultado de verificar una prueba:
 * - valid: firma, vigencia, sesión y trabajo correctos.
 * - missing: la solicitud no trae prueba.
 * - malformed: formato inválido (no es `<desafío>~<solución>` o no decodifica).
 * - invalid-signature: el desafío no lo firmó este servidor (o se alteró).
 * - expired: el desafío venció; el cliente debe pedir uno nuevo.
 * - session-mismatch: el desafío se emitió para otra sesión.
 * - invalid-work: la solución no cumple la dificultad.
 */
export type ProofStatus =
  | "valid"
  | "missing"
  | "malformed"
  | "invalid-signature"
  | "expired"
  | "session-mismatch"
  | "invalid-work";

export interface ProofResult {
  Status: ProofStatus;
  /** Vencimiento del desafío en ms desde epoch; solo si la firma resultó válida. */
  ExpiresAt?: number;
}

/** Veredicto declarado por el cliente (mismo conjunto que BotVerdict del navegador). */
export type ClientVerdict = "unknown" | "human" | "suspicious" | "bot";

/** Contenido interpretado del header de veredicto. Todo lo declara el cliente. */
export interface VerdictHeader {
  Verdict: ClientVerdict;
  /** Puntaje declarado, acotado a 0-100 (0 si falta o no es numérico). */
  Score: number;
  /** Id de sesión de BrowserGuard (`sid`), o null. */
  SessionId: string | null;
  /** Prueba `<desafío>~<solución>`, o null si el cliente aún no la tiene. */
  Proof: string | null;
}

/**
 * Decisión recomendada:
 * - allow: prueba válida y veredicto unknown/human;
 * - challenge: prueba vencida o veredicto suspicious (pedir captcha o limitar);
 * - deny: sin prueba válida (cliente sin JavaScript o header falsificado) o veredicto bot.
 */
export type Decision = "allow" | "challenge" | "deny";

/** Resultado de VerifyRequest. */
export interface RequestVerification {
  Decision: Decision;
  Proof: ProofResult;
  /**
   * Lo que declara el cliente: confiable solo si Proof.Status es "valid", y aun así
   * declarativo. null si el header falta o no se pudo interpretar.
   */
  Verdict: VerdictHeader | null;
}

/**
 * Contenido firmado del desafío. Claves cortas para que el header sea pequeño. Viaja en
 * claro (base64url, no cifrado): no debe contener nada secreto.
 */
interface ChallengePayload {
  /** Versión del formato. */
  v: 1;
  /** Nonce aleatorio de 128 bits: hace único cada desafío (y su prueba de trabajo). */
  n: string;
  /** Emisión, en segundos desde epoch. */
  iat: number;
  /** Vencimiento, en segundos desde epoch. */
  exp: number;
  /** Dificultad exigida, en bits. Va firmada: el cliente no puede rebajarla. */
  d: number;
  /** Sesión a la que se ata el desafío, si se indicó. */
  sid?: string;
}

const Verdicts: readonly ClientVerdict[] = ["unknown", "human", "suspicious", "bot"];

/** Claves HMAC importadas por secreto: importKey es asíncrono y relativamente costoso. */
const KeyCache = new Map<string, Promise<CryptoKey>>();

function Subtle(): SubtleCrypto {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) {
    throw new Error("Web Crypto (crypto.subtle) is not available");
  }
  return subtle;
}

/**
 * Importa el secreto como clave HMAC-SHA-256 no exportable. Lanza si el secreto es
 * demasiado corto: un secreto débil permitiría falsificar desafíos por fuerza bruta.
 */
function ImportKey(secret: string): Promise<CryptoKey> {
  if (secret.length < MinSecretLength) {
    throw new Error(`Secret must be at least ${MinSecretLength} characters`);
  }
  let key = KeyCache.get(secret);
  if (!key) {
    key = Subtle().importKey("raw", EncodeText(secret), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
      "verify",
    ]);
    // Caché acotada: los servidores suelen usar uno o dos secretos (rotación).
    if (KeyCache.size >= 8) {
      KeyCache.clear();
    }
    KeyCache.set(secret, key);
  }
  return key;
}

/** `bytes` bytes aleatorios criptográficamente seguros, en hexadecimal. */
function RandomHex(bytes: number): string {
  const values = (globalThis as { crypto: Crypto }).crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

/**
 * Emite un desafío firmado. Llámalo desde un endpoint (p. ej. GET /api/challenge?sid=...)
 * y devuelve el resultado como JSON. Pasa el `sid` de la query como SessionId para atar
 * el desafío a esa sesión. Lanza si el secreto es demasiado corto o falta Web Crypto.
 */
export async function CreateChallenge(options: ChallengeOptions): Promise<IssuedChallenge> {
  const key = await ImportKey(options.Secret);
  const now = options.Now ?? Date.now();
  // Mínimo de 30 s: con menos, el desafío podría vencer antes de que un dispositivo
  // lento termine la prueba de trabajo.
  const ttl = Math.max(30, Math.round(options.TtlSeconds ?? DefaultTtlSeconds));
  const difficulty = ClampDifficulty(options.Difficulty ?? DefaultDifficulty);
  const payload: ChallengePayload = {
    v: 1,
    n: RandomHex(16),
    iat: Math.floor(now / 1000),
    exp: Math.floor(now / 1000) + ttl,
    d: difficulty,
  };
  if (typeof options.SessionId === "string" && options.SessionId !== "") {
    // Acotado: el sid viene del cliente y termina dentro del header de cada solicitud.
    payload.sid = options.SessionId.slice(0, 128);
  }
  // Se firma el texto base64url exacto que viaja (no el JSON): el verificador compara
  // los mismos bytes sin depender de cómo se re-serialice el JSON.
  const body = ToBase64Url(EncodeText(JSON.stringify(payload)));
  const signature = new Uint8Array(await Subtle().sign("HMAC", key, EncodeText(body)));
  return {
    Challenge: `${body}.${ToBase64Url(signature)}`,
    Difficulty: difficulty,
    ExpiresAt: payload.exp * 1000,
  };
}

/**
 * Decodifica y valida la forma del payload. Solo se llama con la firma ya verificada,
 * pero se valida igual (defensa en profundidad ante un cambio de formato).
 */
function ParsePayload(bytes: Uint8Array): ChallengePayload | null {
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes)) as Partial<ChallengePayload>;
    const valid =
      value.v === 1 &&
      typeof value.n === "string" &&
      typeof value.iat === "number" &&
      typeof value.exp === "number" &&
      typeof value.d === "number" &&
      (value.sid === undefined || typeof value.sid === "string");
    return valid ? (value as ChallengePayload) : null;
  } catch {
    return null;
  }
}

/**
 * Verifica una prueba `<desafío>~<solución>`.
 * La firma se verifica con crypto.subtle.verify (comparación en tiempo constante, sin
 * filtrar por tiempos cuántos bytes de la firma coinciden).
 *
 * Orden de las comprobaciones: primero las baratas (formato), luego la firma y recién
 * después el contenido: nunca se interpreta un payload que no firmó este servidor.
 */
export async function VerifyProof(
  proof: string | null | undefined,
  options: Pick<ChallengeOptions, "Secret" | "SessionId" | "Now">,
): Promise<ProofResult> {
  if (proof === null || proof === undefined || proof === "") {
    return { Status: "missing" };
  }
  // lastIndexOf: "~" no aparece en base64url ni en el desafío, solo como separador.
  const separator = proof.lastIndexOf("~");
  const challenge = proof.slice(0, separator);
  const nonceText = proof.slice(separator + 1);
  const [body, signatureText, extra] = challenge.split(".");
  if (
    separator <= 0 ||
    // Hasta 15 dígitos: siempre un entero seguro, cuyo texto coincide con el hasheado.
    !/^\d{1,15}$/.test(nonceText) ||
    !body ||
    !signatureText ||
    extra !== undefined
  ) {
    return { Status: "malformed" };
  }
  const signature = FromBase64Url(signatureText);
  const payloadBytes = FromBase64Url(body);
  if (!signature || !payloadBytes) {
    return { Status: "malformed" };
  }

  const key = await ImportKey(options.Secret);
  const authentic = await Subtle().verify("HMAC", key, signature, EncodeText(body));
  if (!authentic) {
    return { Status: "invalid-signature" };
  }
  const payload = ParsePayload(payloadBytes);
  if (!payload) {
    return { Status: "malformed" };
  }
  const expiresAt = payload.exp * 1000;
  // El vencimiento solo puede leerse tras verificar la firma: el cliente no puede
  // extender la vigencia editando `exp`.
  if ((options.Now ?? Date.now()) >= expiresAt) {
    return { Status: "expired", ExpiresAt: expiresAt };
  }
  // Un desafío atado a una sesión solo vale junto a ese sid. Como el sid del header
  // también lo declara el cliente, esto no impide reutilizar prueba y sid juntos: sirve
  // para correlacionar con la sesión que el backend registró al emitir. Sin sid, no ata.
  if (payload.sid !== undefined && (options.SessionId ?? null) !== payload.sid) {
    return { Status: "session-mismatch", ExpiresAt: expiresAt };
  }
  // El trabajo se calcula sobre el desafío completo (payload + firma), así que una
  // solución no sirve para otro desafío. ClampDifficulty es defensivo: `d` ya va firmado.
  const solved = await CheckWork(challenge, Number(nonceText), ClampDifficulty(payload.d));
  return { Status: solved ? "valid" : "invalid-work", ExpiresAt: expiresAt };
}

/**
 * Interpreta "X-BrowserGuard-Verdict: <veredicto>; score=<n>; sid=<id>; proof=<prueba>".
 * Retorna null si el valor falta, es demasiado largo o el veredicto no es uno conocido.
 * Los campos desconocidos se ignoran (compatibilidad con versiones futuras).
 */
export function ParseVerdictHeader(value: string | null | undefined): VerdictHeader | null {
  // Límite de longitud: el header es entrada no confiable y se procesa antes de verificar.
  if (typeof value !== "string" || value.length > 4096) {
    return null;
  }
  const [verdict, ...parts] = value.split(";").map((part) => part.trim());
  if (!Verdicts.includes(verdict as ClientVerdict)) {
    return null;
  }
  const fields = new Map<string, string>();
  for (const part of parts) {
    const separator = part.indexOf("=");
    if (separator > 0) {
      fields.set(part.slice(0, separator).trim(), part.slice(separator + 1).trim());
    }
  }
  const score = Number(fields.get("score") ?? 0);
  return {
    Verdict: verdict as ClientVerdict,
    Score: Number.isFinite(score) ? Math.min(100, Math.max(0, score)) : 0,
    SessionId: fields.get("sid") ?? null,
    Proof: fields.get("proof") ?? null,
  };
}

/** Headers de una solicitud: objeto Headers (fetch/edge) u objeto plano (Node). */
type HeaderSource =
  { get(name: string): string | null } | Record<string, string | string[] | undefined>;

/**
 * Lee un header sin distinguir mayúsculas. En un objeto plano de Node un header repetido
 * llega como arreglo: se toma el primero.
 */
function ReadHeader(headers: HeaderSource, name: string): string | null {
  if (typeof (headers as { get?: unknown }).get === "function") {
    return (headers as { get(name: string): string | null }).get(name);
  }
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(
    headers as Record<string, string | string[] | undefined>,
  )) {
    if (key.toLowerCase() === lower) {
      return Array.isArray(value) ? (value[0] ?? null) : (value ?? null);
    }
  }
  return null;
}

/**
 * Verifica los headers de una solicitud y recomienda una decisión.
 * Acepta un objeto Headers (fetch, edge) o un objeto plano (Node `req.headers`).
 * La sesión se toma del propio header (`sid`): asegura que prueba y sid declarado
 * coincidan. La decisión es una recomendación; aplicarla es tarea del backend.
 * Lanza (promesa rechazada) si el secreto es demasiado corto o falta Web Crypto.
 */
export async function VerifyRequest(
  headers: HeaderSource,
  options: { Secret: string; HeaderName?: string; Now?: number },
): Promise<RequestVerification> {
  const verdict = ParseVerdictHeader(
    ReadHeader(headers, options.HeaderName ?? "X-BrowserGuard-Verdict"),
  );
  const proof = await VerifyProof(verdict?.Proof, {
    Secret: options.Secret,
    SessionId: verdict?.SessionId ?? null,
    Now: options.Now,
  });

  // Una prueba vencida pero auténtica es de un cliente que debe renovar el desafío: se
  // pide uno nuevo en lugar de denegar, incluso con veredicto "bot" (que es declarado).
  let decision: Decision;
  if (proof.Status === "expired") {
    decision = "challenge";
  } else if (proof.Status !== "valid" || verdict?.Verdict === "bot") {
    decision = "deny";
  } else {
    decision = verdict?.Verdict === "suspicious" ? "challenge" : "allow";
  }
  return { Decision: decision, Proof: proof, Verdict: verdict };
}
