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

export const DefaultDifficulty = 14;
export const DefaultTtlSeconds = 600;

export interface ChallengeOptions {
  /** Secreto HMAC del servidor (mínimo 32 caracteres). Nunca se envía al cliente. */
  Secret: string;
  /** Bits en cero exigidos (8-24). Cada bit duplica el trabajo. Por defecto: 14. */
  Difficulty?: number;
  /** Vigencia del desafío, en segundos. Por defecto: 600. */
  TtlSeconds?: number;
  /** Ata el desafío a una sesión de BrowserGuard (parámetro `sid` de la solicitud). */
  SessionId?: string | null;
  /** Reloj, en ms (para tests). */
  Now?: number;
}

export interface IssuedChallenge {
  Challenge: string;
  Difficulty: number;
  /** Vencimiento en ms desde epoch. */
  ExpiresAt: number;
}

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
  ExpiresAt?: number;
}

export type ClientVerdict = "unknown" | "human" | "suspicious" | "bot";

export interface VerdictHeader {
  Verdict: ClientVerdict;
  Score: number;
  SessionId: string | null;
  Proof: string | null;
}

/**
 * Decisión recomendada:
 * - allow: prueba válida y veredicto unknown/human;
 * - challenge: prueba vencida o veredicto suspicious (pedir captcha o limitar);
 * - deny: sin prueba válida (cliente sin JavaScript o header falsificado) o veredicto bot.
 */
export type Decision = "allow" | "challenge" | "deny";

export interface RequestVerification {
  Decision: Decision;
  Proof: ProofResult;
  /** Lo que declara el cliente: confiable solo si Proof.Status es "valid", y aun así declarativo. */
  Verdict: VerdictHeader | null;
}

interface ChallengePayload {
  v: 1;
  n: string;
  iat: number;
  exp: number;
  d: number;
  sid?: string;
}

const Verdicts: readonly ClientVerdict[] = ["unknown", "human", "suspicious", "bot"];

const KeyCache = new Map<string, Promise<CryptoKey>>();

function Subtle(): SubtleCrypto {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) {
    throw new Error("Web Crypto (crypto.subtle) is not available");
  }
  return subtle;
}

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

function RandomHex(bytes: number): string {
  const values = (globalThis as { crypto: Crypto }).crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

/**
 * Emite un desafío firmado. Llámalo desde un endpoint (p. ej. GET /api/challenge?sid=...)
 * y devuelve el resultado como JSON.
 */
export async function CreateChallenge(options: ChallengeOptions): Promise<IssuedChallenge> {
  const key = await ImportKey(options.Secret);
  const now = options.Now ?? Date.now();
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
    payload.sid = options.SessionId.slice(0, 128);
  }
  const body = ToBase64Url(EncodeText(JSON.stringify(payload)));
  const signature = new Uint8Array(await Subtle().sign("HMAC", key, EncodeText(body)));
  return {
    Challenge: `${body}.${ToBase64Url(signature)}`,
    Difficulty: difficulty,
    ExpiresAt: payload.exp * 1000,
  };
}

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
 * La firma se verifica con crypto.subtle.verify (comparación en tiempo constante).
 */
export async function VerifyProof(
  proof: string | null | undefined,
  options: Pick<ChallengeOptions, "Secret" | "SessionId" | "Now">,
): Promise<ProofResult> {
  if (proof === null || proof === undefined || proof === "") {
    return { Status: "missing" };
  }
  const separator = proof.lastIndexOf("~");
  const challenge = proof.slice(0, separator);
  const nonceText = proof.slice(separator + 1);
  const [body, signatureText, extra] = challenge.split(".");
  if (
    separator <= 0 ||
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
  if ((options.Now ?? Date.now()) >= expiresAt) {
    return { Status: "expired", ExpiresAt: expiresAt };
  }
  if (payload.sid !== undefined && (options.SessionId ?? null) !== payload.sid) {
    return { Status: "session-mismatch", ExpiresAt: expiresAt };
  }
  const solved = await CheckWork(challenge, Number(nonceText), ClampDifficulty(payload.d));
  return { Status: solved ? "valid" : "invalid-work", ExpiresAt: expiresAt };
}

/**
 * Interpreta "X-BrowserGuard-Verdict: <veredicto>; score=<n>; sid=<id>; proof=<prueba>".
 */
export function ParseVerdictHeader(value: string | null | undefined): VerdictHeader | null {
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

type HeaderSource =
  { get(name: string): string | null } | Record<string, string | string[] | undefined>;

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
