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

// Canales de exfiltración distintos de fetch/XHR.
function leakWithImage(url) {
  new Image().src = url;
}

function leakWithBeacon(url) {
  return navigator.sendBeacon(url, "data");
}

function submitFormTo(url) {
  // El formulario apunta a un iframe para no navegar fuera de la página de prueba.
  const frame = document.createElement("iframe");
  frame.name = "form-sink";
  document.body.appendChild(frame);
  const form = document.createElement("form");
  form.method = "post";
  form.action = url;
  form.target = "form-sink";
  form.innerHTML = '<input name="password" value="hunter2">';
  document.body.appendChild(form);
  form.submit();
}

function openWindowTo(url) {
  window.open(url)?.close();
}

function openStream(url) {
  new EventSource(url).close();
}

function registerWorker() {
  return navigator.serviceWorker.register("/fixtures/sw.js");
}

// Evasión clásica: obtener un fetch "limpio" desde un iframe vacío.
function fetchThroughFrame(url) {
  const frame = document.createElement("iframe");
  document.body.appendChild(frame);
  return frame.contentWindow.fetch(url).catch(() => null);
}

function fetchThroughFrameDocument(url) {
  const frame = document.createElement("iframe");
  document.body.appendChild(frame);
  return frame.contentDocument.defaultView.fetch(url).catch(() => null);
}

function insertBlankFrame() {
  document.body.appendChild(document.createElement("iframe"));
}

function fetchThroughFramesIndex(url) {
  return window.frames[window.frames.length - 1].fetch(url).catch(() => null);
}

function talkToCrossOriginFrame(url) {
  const frame = document.createElement("iframe");
  frame.src = url;
  document.body.appendChild(frame);
  return new Promise((resolve) => {
    frame.addEventListener("load", () => {
      frame.contentWindow.postMessage("hello", "*");
      resolve(true);
    });
  });
}

function setDangerousUrls() {
  document.createElement("a").href = "javascript:alert(document.cookie)";
  document.createElement("button").formAction = "javascript:steal()";
  document.createElement("iframe").src = "javascript:steal()";
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
  leakWithImage,
  leakWithBeacon,
  submitFormTo,
  openWindowTo,
  openStream,
  registerWorker,
  fetchThroughFrame,
  fetchThroughFrameDocument,
  insertBlankFrame,
  fetchThroughFramesIndex,
  talkToCrossOriginFrame,
  setDangerousUrls,
};
