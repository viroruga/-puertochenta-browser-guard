---
"@puertochenta/browser-guard": minor
---

Server-verifiable anti-scraping challenge.

- New entry point `@puertochenta/browser-guard/server` (Web Crypto only: Node, Deno, Bun, edge):
  `CreateChallenge` issues HMAC-signed, session-bound, expiring challenges; `VerifyRequest`
  verifies the proof in the verdict header and returns a recommended `allow` / `challenge` /
  `deny` decision.
- `AntiScraping({ Challenge: { Endpoint } })` fetches the challenge with the original `fetch`,
  solves a proof of work asynchronously, renews it before it expires and appends it to the
  verdict header. `GetBotAssessment().Proof` reports `pending` / `ready` / `failed`.
- Forged verdict headers and clients without JavaScript are now rejected by the server; the
  proof does not prove the client is human (documented).
