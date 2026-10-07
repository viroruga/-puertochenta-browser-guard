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

// Sinks de DOM XSS: patrones vulnerables típicos.
function renderComment(html) {
  const container = document.createElement("div");
  container.innerHTML = html;
  document.body.appendChild(container);
  return container;
}

function renderSearchFromUrl() {
  // Vulnerable a propósito: escribe en innerHTML un valor tomado de la URL.
  const query = new URLSearchParams(location.search).get("q") ?? "";
  const container = document.createElement("div");
  container.innerHTML = `Results for ${query}`;
  document.body.appendChild(container);
}

function runLater(code) {
  setTimeout(code, 0);
}

window.App = {
  submitPayment,
  sendLegacyRequest,
  openSocket,
  injectScript,
  loadExternalImage,
  renderComment,
  renderSearchFromUrl,
  runLater,
};
