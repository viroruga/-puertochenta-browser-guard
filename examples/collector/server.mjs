// Colector de ejemplo para BrowserGuard (Remote.Endpoint).
//
// Recibe hallazgos por POST /findings, los imprime en la terminal, los guarda en
// data/findings.jsonl y los muestra en un panel en GET /.
//
// Es un ejemplo de desarrollo. Todo lo que llega es NO CONFIABLE: cualquiera puede
// enviar hallazgos falsos a un endpoint público. En producción agrega autenticación
// de origen, rate limiting real, validación de esquema y almacenamiento adecuado.

import { appendFile, mkdir } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const Port = Number(process.env.PORT ?? 8787);
const Host = process.env.HOST ?? "127.0.0.1";
const AllowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS ?? "http://localhost:5173,http://127.0.0.1:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
);
const MaxBodyBytes = 256 * 1024;
const MaxFindingsPerRequest = 100;
const MaxRequestsPerMinute = 120;
const MaxStoredInMemory = 500;
const Schema = "browser-guard.findings/v1";

// Verificación anti-scraping. En tu backend: import { ... } from "@puertochenta/browser-guard/server".
// En este repositorio se usa el bundle compilado: ejecuta `pnpm build` en la raíz antes.
const { CreateChallenge, VerifyRequest } = await import("../../dist/server.js").catch(() => {
  console.error("dist/server.js not found: run `pnpm build` in the repository root first.");
  process.exit(1);
});

// Secreto HMAC del servidor: en producción, un valor aleatorio largo guardado como secreto.
const ChallengeSecret =
  process.env.CHALLENGE_SECRET ?? "development-only-secret-change-me-0123456789";
if (!process.env.CHALLENGE_SECRET) {
  console.warn("Using a development CHALLENGE_SECRET. Set CHALLENGE_SECRET in production.");
}

const DataFile = join(dirname(fileURLToPath(import.meta.url)), "data", "findings.jsonl");
const Recent = [];
const RequestCounts = new Map();

const Colors = { critical: 41, high: 31, medium: 33, low: 34, info: 90 };

function Escape(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char],
  );
}

function IsRateLimited(ip) {
  const minute = Math.floor(Date.now() / 60_000);
  const entry = RequestCounts.get(ip);
  if (!entry || entry.Minute !== minute) {
    RequestCounts.set(ip, { Minute: minute, Count: 1 });
    return false;
  }
  entry.Count++;
  return entry.Count > MaxRequestsPerMinute;
}

function ApplyCors(request, response) {
  const origin = request.headers.origin;
  if (origin && AllowedOrigins.has(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Vary", "Origin");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    response.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, X-Ingest-Key, X-BrowserGuard-Verdict",
    );
    response.setHeader("Access-Control-Max-Age", "600");
  }
}

function ReadBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MaxBodyBytes) {
        reject(new Error("payload too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

/**
 * Valida la forma mínima del payload. sendBeacon envía text/plain, por eso se
 * parsea el cuerpo como JSON sin depender del Content-Type.
 */
function ParsePayload(body) {
  const payload = JSON.parse(body);
  if (payload?.Schema !== Schema || !Array.isArray(payload.Findings)) {
    throw new Error("invalid schema");
  }
  if (payload.Findings.length > MaxFindingsPerRequest) {
    throw new Error("too many findings");
  }
  return payload;
}

function PrintFinding(finding, payload, ip) {
  const color = Colors[finding.Severity] ?? 0;
  const severity = `\x1b[${color}m ${String(finding.Severity).toUpperCase()} \x1b[0m`;
  const page = `${payload.Page?.Origin ?? "?"}${payload.Page?.Path ?? ""}`;
  console.log(`${severity} ${finding.RiskScore}/100 ${finding.Category} · ${finding.Title}`);
  console.log(`   page: ${page}  session: ${String(payload.SessionId).slice(0, 8)}  ip: ${ip}`);
  if (finding.Stack) {
    console.log(`   stack: ${String(finding.Stack).split("\n")[0]}`);
  }
}

async function HandleFindings(request, response, ip) {
  if (IsRateLimited(ip)) {
    response.writeHead(429).end();
    return;
  }
  let payload;
  try {
    payload = ParsePayload(await ReadBody(request));
  } catch (error) {
    response.writeHead(error.message === "payload too large" ? 413 : 400).end();
    return;
  }

  const receivedAt = Date.now();
  const records = payload.Findings.map((finding) => ({
    ReceivedAt: receivedAt,
    Ip: ip,
    SessionId: payload.SessionId,
    Page: payload.Page,
    Metadata: payload.Metadata,
    Finding: finding,
  }));
  for (const record of records) {
    PrintFinding(record.Finding, payload, ip);
    Recent.push(record);
  }
  Recent.splice(0, Math.max(0, Recent.length - MaxStoredInMemory));

  await mkdir(dirname(DataFile), { recursive: true });
  await appendFile(DataFile, records.map((record) => JSON.stringify(record)).join("\n") + "\n");
  response.writeHead(204).end();
}

const Catalog = [
  { Id: 1, Name: "Industrial drill", WholesalePrice: 1249 },
  { Id: 2, Name: "Safety gloves", WholesalePrice: 19 },
  { Id: 3, Name: "Laser level", WholesalePrice: 310 },
];

/**
 * Emite un desafío firmado para la sesión de BrowserGuard (parámetro `sid`).
 * El navegador lo resuelve y envía la prueba en el header de veredicto.
 */
async function HandleChallenge(url, response, ip) {
  if (IsRateLimited(ip)) {
    response.writeHead(429).end();
    return;
  }
  const issued = await CreateChallenge({
    Secret: ChallengeSecret,
    SessionId: url.searchParams.get("sid"),
  });
  response.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(issued));
}

const DecisionStatus = { allow: 200, challenge: 429, deny: 403 };

/**
 * Endpoint de ejemplo protegido por la verificación del servidor:
 * - sin prueba válida (curl, requests, Scrapy, header falsificado) -> deny (403);
 * - veredicto bot -> deny (403); suspicious o prueba vencida -> challenge (429:
 *   en un caso real, pedir un captcha);
 * - prueba válida y veredicto unknown/human -> allow (200).
 *
 * La prueba demuestra que el cliente ejecutó BrowserGuard y gastó CPU, no que sea
 * humano: combínalo con rate limiting por sesión (Verdict.SessionId) e IP.
 */
async function HandleCatalog(request, response, ip) {
  if (IsRateLimited(ip)) {
    response.writeHead(429).end();
    return;
  }
  const result = await VerifyRequest(request.headers, { Secret: ChallengeSecret });
  const status = DecisionStatus[result.Decision];
  console.log(
    `\x1b[36m API \x1b[0m GET /api/catalog -> ${status} (decision: ${result.Decision}, proof: ${result.Proof.Status}, verdict: ${result.Verdict?.Verdict ?? "missing"}, ip: ${ip})`,
  );
  const body =
    result.Decision === "allow"
      ? { Verdict: result.Verdict?.Verdict, Items: Catalog }
      : { Decision: result.Decision, Proof: result.Proof.Status };
  response.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(body));
}

function RenderDashboard() {
  const rows = [...Recent]
    .reverse()
    .map(({ ReceivedAt, Page, SessionId, Metadata, Finding }) => {
      const severity = Escape(Finding?.Severity);
      return `<tr class="${severity}">
  <td>${Escape(new Date(ReceivedAt).toLocaleTimeString())}</td>
  <td><span class="badge">${severity}</span></td>
  <td>${Escape(Finding?.RiskScore)}</td>
  <td>${Escape(Finding?.Category)}</td>
  <td><strong>${Escape(Finding?.Title)}</strong><br><small>${Escape(Finding?.Description)}</small>${
    Finding?.Stack ? `<pre>${Escape(Finding.Stack)}</pre>` : ""
  }</td>
  <td>${Escape(Page?.Origin)}${Escape(Page?.Path)}<br><small>${Escape(String(SessionId).slice(0, 8))}${
    Metadata ? ` · ${Escape(JSON.stringify(Metadata))}` : ""
  }</small></td>
</tr>`;
    })
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>BrowserGuard Collector</title>
<style>
  :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
  body { margin: 0; padding: 16px; }
  h1 { font-size: 1.2rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { text-align: left; vertical-align: top; padding: 8px; border-bottom: 1px solid #8884; }
  pre { margin: 6px 0 0; font-size: 0.75rem; white-space: pre-wrap; opacity: 0.8; }
  small { opacity: 0.75; }
  .badge { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; padding: 2px 8px; border-radius: 999px; color: #fff; background: #546e7a; }
  .critical .badge { background: #b00020; } .high .badge { background: #e65100; }
  .medium .badge { background: #c98a00; } .low .badge { background: #1565c0; }
  .table-wrap { overflow-x: auto; }
</style>
</head>
<body>
<h1>BrowserGuard Collector · ${Recent.length} finding(s) · refreshes every 5 s</h1>
<div class="table-wrap">
<table>
<thead><tr><th>Received</th><th>Severity</th><th>Risk</th><th>Category</th><th>Finding</th><th>Page / session</th></tr></thead>
<tbody>${rows || '<tr><td colspan="6">No findings yet.</td></tr>'}</tbody>
</table>
</div>
</body>
</html>`;
}

const server = createServer((request, response) => {
  const ip = request.socket.remoteAddress ?? "unknown";
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
  ApplyCors(request, response);

  if (url.pathname === "/api/challenge" && request.method === "GET") {
    HandleChallenge(url, response, ip).catch(() => response.writeHead(500).end());
    return;
  }
  if (url.pathname === "/api/catalog" && request.method === "GET") {
    HandleCatalog(request, response, ip).catch(() => response.writeHead(500).end());
    return;
  }
  if (
    (url.pathname === "/findings" ||
      url.pathname === "/api/catalog" ||
      url.pathname === "/api/challenge") &&
    request.method === "OPTIONS"
  ) {
    response.writeHead(204).end();
    return;
  }
  if (url.pathname === "/findings" && request.method === "POST") {
    HandleFindings(request, response, ip).catch(() => {
      if (!response.headersSent) {
        response.writeHead(500).end();
      }
    });
    return;
  }
  if (url.pathname === "/api/findings" && request.method === "GET") {
    response.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(Recent));
    return;
  }
  if (url.pathname === "/" && request.method === "GET") {
    // Los hallazgos son datos no confiables: además de escaparlos, el panel no
    // permite ejecutar scripts ni cargar recursos externos.
    response
      .writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
        "X-Content-Type-Options": "nosniff",
      })
      .end(RenderDashboard());
    return;
  }
  response.writeHead(404).end();
});

server.listen(Port, Host, () => {
  console.log(`BrowserGuard collector listening on http://${Host}:${Port}`);
  console.log(
    `  POST http://${Host}:${Port}/findings   (allowed origins: ${[...AllowedOrigins].join(", ")})`,
  );
  console.log(`  Dashboard: http://${Host}:${Port}/`);
});
