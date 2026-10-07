/**
 * Punto de entrada "@puertochenta/browser-guard/server": verificación en el backend del
 * header de veredicto anti-scraping. No depende del DOM; usa solo Web Crypto.
 */
export {
  CreateChallenge,
  DefaultDifficulty,
  DefaultTtlSeconds,
  MinSecretLength,
  ParseVerdictHeader,
  VerifyProof,
  VerifyRequest,
} from "./Challenge";
export type {
  ChallengeOptions,
  ClientVerdict,
  Decision,
  IssuedChallenge,
  ProofResult,
  ProofStatus,
  RequestVerification,
  VerdictHeader,
} from "./Challenge";
