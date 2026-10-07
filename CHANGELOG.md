# @puertochenta/browser-guard

## 0.1.0

Initial release.

### Features

- **Runtime monitors:** `fetch`, `XMLHttpRequest`, `WebSocket`, DOM insertion of `script` /
  `iframe` / `object` / `embed`, CSP violations, native prototypes and critical runtime
  functions. Transparent `Proxy`-based interception with exact restoration on `Stop()`.
- **Detectors and risk scoring:** network origins, script injection, CSP, prototype pollution
  and runtime integrity, scored 0-100 with configurable signal weights.
- **Presets:** `development`, `balanced`, `strict` and `forensic`, with a bounded forensic
  timeline.
- **Console modes:** `notice` (default outside development: end users only see a monitoring
  notice), `findings` and `silent`.
- **Plugin system:** optional features ship on separate entry points
  (`@puertochenta/browser-guard/anti-scraping`, `@puertochenta/browser-guard/remote`), so the core
  bundle stays at ~13 KB gzip. Custom plugins and reporters are supported.
- **`RemoteReporting` plugin:** batched delivery to your endpoint with retries, `sendBeacon` on
  page hide, bounded payloads and no cookies or referrer.
- **`AntiScraping` plugin:** automation, environment, request-rate and interaction signals;
  per-session verdict; removal of protected content from the DOM; verdict header for
  server-side enforcement.
- **Useful stack traces in production bundles:** internal frames are dropped by position, so
  stacks point to application code even when the library shares a file with it.
- **Privacy by design:** sanitized URLs and evidence (tokens, cookies, JWTs, card numbers are
  never recorded), no fingerprinting, local by default.
- **SSR-safe** import (Next.js, Nuxt).
