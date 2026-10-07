---
"@puertochenta/browser-guard": minor
---

Observe more exfiltration channels and close the clean-realm evasion.

- `ChannelMonitor`: `sendBeacon`, `EventSource`, `window.open`, form submissions and service
  worker registration. `ResourceMonitor`: resource downloads (images, CSS, fonts...) through
  `PerformanceObserver`, without patching any API. Queries are never recorded, only their length:
  long queries to unknown origins raise the risk (exfiltration pattern). Equivalent network
  findings are grouped for 10 seconds.
- `RealmMonitor`: when a script reaches the realm of a same-origin iframe, the network, channel and
  sink monitors are installed in it before the value is returned, so the classic
  `iframe.contentWindow.fetch` evasion is observed.
- `SinkMonitor` also observes `javascript:` URLs assigned through `href`, `src`, `action`,
  `formAction` and `data`.
- New monitor toggles: `Channels` and `Realms` (enabled by default).
- End-to-end tests now also run on WebKit.

Core bundle: +2.3 KB gzip (18.0 KB for an app that imports only the core).
