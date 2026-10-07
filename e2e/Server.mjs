// Servidor de pruebas end-to-end (sin dependencias).
//
// - /dist/*      → bundle compilado (lo que se publica en npm).
// - /fixtures/*  → páginas de prueba.
// - /api/echo    → devuelve los headers de interés (header de veredicto anti-scraping).
// - /collect     → recibe el envío remoto; GET /collected lo devuelve; POST /reset lo vacía.
//
// "localhost" y "127.0.0.1" son orígenes distintos para el navegador: los tests
// usan ambos para probar casos cross-origin sin un segundo servidor.

import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const Root = dirname(dirname(fileURLToPath(import.meta.url)));
const Port = Number(process.env.E2E_PORT ?? 4173);
const ServedDirectories = {
  "/dist/": join(Root, "dist"),
  "/fixtures/": join(Root, "e2e", "fixtures"),
};
const ContentTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".map": "application/json",
  ".json": "application/json",
  ".png": "image/png",
};

let Collected = [];

function Cors(request, response) {
  const origin = request.headers.origin;
  if (origin) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type, X-BrowserGuard-Verdict");
  }
}

function ReadBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

async function ServeFile(pathname, response) {
  for (const [prefix, directory] of Object.entries(ServedDirectories)) {
    if (!pathname.startsWith(prefix)) {
      continue;
    }
    const file = normalize(join(directory, pathname.slice(prefix.length)));
    if (!file.startsWith(directory + sep)) {
      break;
    }
    try {
      const content = await readFile(file);
      response.writeHead(200, {
        "Content-Type": ContentTypes[extname(file)] ?? "application/octet-stream",
        "Cache-Control": "no-store",
      });
      response.end(content);
      return;
    } catch {
      break;
    }
  }
  response.writeHead(404).end();
}

const server = createServer((request, response) => {
  // Un error en un handler nunca debe terminar el servidor: afectaría a todos los tests.
  Handle(request, response).catch(() => {
    if (!response.headersSent) {
      response.writeHead(500);
    }
    response.end();
  });
});

async function Handle(request, response) {
  const url = new URL(request.url ?? "/", "http://localhost");
  Cors(request, response);

  if (request.method === "OPTIONS") {
    response.writeHead(204).end();
    return;
  }
  if (url.pathname === "/api/echo") {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ Verdict: request.headers["x-browserguard-verdict"] ?? null }));
    return;
  }
  if (url.pathname === "/collect" && request.method === "POST") {
    // Solo se guardan payloads JSON (envío remoto); otros cuerpos (p. ej. un beacon de
    // prueba con texto) se aceptan sin guardarse.
    const body = await ReadBody(request);
    try {
      Collected.push(JSON.parse(body));
    } catch {
      // Cuerpo no JSON: se ignora.
    }
    response.writeHead(204).end();
    return;
  }
  if (url.pathname === "/collected") {
    response.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(Collected));
    return;
  }
  if (url.pathname === "/reset" && request.method === "POST") {
    Collected = [];
    response.writeHead(204).end();
    return;
  }
  if (url.pathname.startsWith("/product/")) {
    response.writeHead(200, { "Content-Type": "application/json" }).end("{}");
    return;
  }
  await ServeFile(url.pathname, response);
}

server.listen(Port, () => {
  console.log(`e2e server on http://localhost:${Port}`);
});
