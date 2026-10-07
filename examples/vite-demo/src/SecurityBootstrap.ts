// SecurityBootstrap.ts
//
// Debe importarse antes que cualquier otro módulo de la aplicación para que
// BrowserGuard observe el runtime desde el inicio.

import { BrowserGuard, type BrowserGuardConfig } from "@puertochenta/browser-guard";
import { AntiScraping } from "@puertochenta/browser-guard/anti-scraping";
import { RemoteReporting } from "@puertochenta/browser-guard/remote";

export const GuardConfig: BrowserGuardConfig = {
  Preset: "development",
  // En consola el usuario final solo ve el aviso; los hallazgos llegan por código
  // (Guard.On) y en esta demo se listan en la página. Usa "findings" para depurar.
  Console: "notice",
  Notice: {
    Title: "Monitoreo de seguridad activo",
    Message:
      "Esta página está protegida por monitoreo de seguridad en tiempo de ejecución. La actividad sospechosa se detecta y se reporta al proveedor del sitio. No pegues ni ejecutes aquí código que no entiendas: podría dar a terceros acceso a tu cuenta.",
  },
  Plugins: [
    // Envía los hallazgos al colector de ejemplo (examples/collector: pnpm start).
    RemoteReporting({
      Endpoint: "http://localhost:8787/findings",
      BatchSize: 5,
      FlushIntervalMs: 2000,
      Metadata: { App: "vite-demo", Environment: "development" },
    }),
    // Protección anti-scraping: el veredicto viaja en un header hacia la API del colector,
    // que lo usa para rechazar bots y clientes que no ejecutan BrowserGuard.
    AntiScraping({
      Placeholder: "Contenido no disponible.",
      VerdictHeader: { Origins: ["http://localhost:8787"] },
    }),
  ],
  Network: {
    AllowedOrigins: [window.location.origin, "https://api.example.com", "http://localhost:8787"],
    BlockedOrigins: ["https://evil.example"],
  },
  Dom: {
    AllowedScriptOrigins: [window.location.origin, "https://cdn.example.com"],
  },
};

export const Guard = BrowserGuard.Start(GuardConfig);
