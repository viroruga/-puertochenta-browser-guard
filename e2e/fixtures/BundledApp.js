// Aplicación empaquetada junto con BrowserGuard en un único archivo (como un build de
// producción de Vite/webpack). Verifica que el stack trace siga apuntando al código de
// la aplicación aunque comparta archivo con la librería.
import { BrowserGuard } from "../../dist/index.js";

function submitBundledPayment(url) {
  return fetch(url).catch(() => null);
}

window.BrowserGuard = BrowserGuard;
window.BundledApp = { submitBundledPayment };
