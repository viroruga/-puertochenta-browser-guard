import type { BrowserGuard } from "../src/Index";
import type { AntiScraping } from "../src/Plugins/AntiScrapingPlugin";
import type { RemoteReporting } from "../src/Plugins/RemoteReportingPlugin";

/**
 * Globales que exponen las páginas de prueba (e2e/fixtures).
 */
declare global {
  interface Window {
    BrowserGuard: typeof BrowserGuard;
    Guard: BrowserGuard;
    Plugins: { AntiScraping: typeof AntiScraping; RemoteReporting: typeof RemoteReporting };
    Originals: {
      fetch: typeof fetch;
      open: XMLHttpRequest["open"];
      send: XMLHttpRequest["send"];
      WebSocket: typeof WebSocket;
      innerHTMLSetter: (value: string) => void;
      setTimeout: typeof setTimeout;
    };
    App: {
      submitPayment(url: string): Promise<unknown>;
      sendLegacyRequest(url: string): XMLHttpRequest;
      openSocket(url: string): WebSocket;
      injectScript(src: string): void;
      loadExternalImage(src: string): void;
      renderComment(html: string): HTMLDivElement;
      renderSearchFromUrl(): void;
      runLater(code: string): void;
    };
  }
}

export {};
