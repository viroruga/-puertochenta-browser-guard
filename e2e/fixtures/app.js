// "Aplicación" de prueba: funciones con nombre para verificar que los stack traces
// apunten a este archivo y no a los frames internos de BrowserGuard.

function submitPayment(url) {
  return fetch(url).catch(() => null);
}

function sendLegacyRequest(url) {
  const request = new XMLHttpRequest();
  request.open("POST", url);
  request.send("payload");
  return request;
}

function openSocket(url) {
  const socket = new WebSocket(url);
  socket.addEventListener("error", () => undefined);
  return socket;
}

function injectScript(src) {
  const script = document.createElement("script");
  script.src = src;
  script.addEventListener("error", () => script.remove());
  document.head.appendChild(script);
}

function loadExternalImage(src) {
  const image = new Image();
  image.src = src;
}

window.App = { submitPayment, sendLegacyRequest, openSocket, injectScript, loadExternalImage };
