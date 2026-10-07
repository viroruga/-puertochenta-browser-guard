---
"@puertochenta/browser-guard": minor
---

Developer experience: reactive state, known services and learning mode.

- `Guard.Subscribe(listener)` / `Guard.GetSnapshot()`: an observable store with immutable
  snapshots (`Running`, `Bot`, `LastFinding`, `Statistics`), compatible with React's
  `useSyncExternalStore`, Vue refs, Angular signals and Svelte stores, with no framework
  dependency. Changes in the challenge proof state are now published in the `Bot` event too.
- `Services: [...]`: catalog of well-known third parties (Stripe, PayPal, Google Analytics, Tag
  Manager, Fonts, reCAPTCHA, Turnstile, YouTube, Sentry, Hotjar, Intercom, zone.js) that extends
  the allowed origins. Wrappers installed by Sentry and zone.js are recognized by following their
  markers back to the legitimate function, only for declared services.
- `Learning: { Enabled: true }` + `GetLearnedConfig()`: records third-party origins that are not
  allowed yet and proposes the configuration to add.
