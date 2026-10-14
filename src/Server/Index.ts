/**
 * Punto de entrada "@puertochenta/browser-guard/server": verificación en el backend del
 * header de veredicto anti-scraping. No depende del DOM; usa solo Web Crypto, por lo que
 * corre en Node 18+, Deno, Bun y entornos edge.
 *
 * Uso típico: un endpoint de desafíos que responde CreateChallenge() y, en las rutas a
 * proteger, VerifyRequest() sobre los headers de la solicitud.
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
