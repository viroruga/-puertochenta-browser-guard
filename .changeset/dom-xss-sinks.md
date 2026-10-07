---
"@puertochenta/browser-guard": minor
---

Detect DOM XSS in dangerous sinks. The new `SinkMonitor` observes the `innerHTML` / `outerHTML`
setters, `insertAdjacentHTML`, `document.write`, `Range.createContextualFragment`, `iframe.srcdoc`,
`setAttribute` (event handlers and `javascript:` URLs) and string timers, and `XssSinkDetector`
scores the written content by indicators (auto-firing handlers, `<script>`, `javascript:` URLs,
sensitive data access, proof-of-concept calls and values reflected from the page URL). Content is
never recorded. Enabled by default; disable with `Monitors: { Sinks: false }`. `eval` and
`new Function` are intentionally not intercepted to preserve language semantics.

Core bundle: +2.4 KB gzip (15.7 KB for an app that imports only the core).
