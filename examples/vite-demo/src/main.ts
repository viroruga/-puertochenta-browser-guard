// main.ts
// SecurityBootstrap va primero para que BrowserGuard se inicie antes que el resto.
import { Guard, GuardConfig } from "./SecurityBootstrap";

import { BrowserGuard, type SecurityFinding } from "@puertochenta/browser-guard";
import { Simulations } from "./Simulations";
import "./style.css";

let ActiveGuard: BrowserGuard = Guard;

const List = document.querySelector<HTMLOListElement>("#findings");
const Counter = document.querySelector<HTMLSpanElement>("#counter");
const Status = document.querySelector<HTMLParagraphElement>("#status");
const Verdict = document.querySelector<HTMLSpanElement>("#verdict");
const Catalog = document.querySelector<HTMLPreElement>("#catalog");

function RenderVerdict(): void {
  const assessment = ActiveGuard.GetBotAssessment();
  if (Verdict) {
    Verdict.textContent = assessment ? `verdict: ${assessment.Verdict} (${assessment.Score})` : "";
    Verdict.dataset.verdict = assessment?.Verdict ?? "";
  }
}

async function LoadCatalog(): Promise<void> {
  if (!Catalog) {
    return;
  }
  try {
    // BrowserGuard agrega el header X-BrowserGuard-Verdict a esta solicitud.
    const response = await fetch("http://localhost:8787/api/catalog");
    Catalog.textContent = `Catalog API -> ${response.status}\n${await response.text()}`;
  } catch {
    Catalog.textContent = "Catalog API unreachable: start examples/collector (pnpm start).";
  }
}

function RenderStatus(): void {
  const status = ActiveGuard.GetStatus();
  const running = status.Monitors.filter((monitor) => monitor.Running).length;
  if (Status) {
    Status.textContent = status.Running
      ? `Running · preset "${status.Preset}" · ${running}/${status.Monitors.length} monitors active`
      : "Stopped · all interceptors restored";
    Status.dataset.running = String(status.Running);
  }
  if (Counter) {
    Counter.textContent = `(${ActiveGuard.GetReport().Statistics.Total})`;
  }
}

function RenderFinding(finding: SecurityFinding): void {
  if (!List) {
    return;
  }
  const item = document.createElement("li");
  item.className = `finding ${finding.Severity}`;

  const header = document.createElement("div");
  header.className = "finding-header";
  const badge = document.createElement("span");
  badge.className = "badge";
  badge.textContent = finding.Severity;
  const title = document.createElement("strong");
  title.textContent = finding.Title;
  const score = document.createElement("span");
  score.className = "score";
  score.textContent = `${finding.RiskScore}/100 · ${finding.Category}`;
  header.append(badge, title, score);

  const description = document.createElement("p");
  description.textContent = finding.Description;
  item.append(header, description);

  if (finding.Stack) {
    const stack = document.createElement("pre");
    stack.textContent = finding.Stack;
    item.append(stack);
  }

  List.prepend(item);
  RenderStatus();
}

function Subscribe(guard: BrowserGuard): void {
  guard.On("Finding", RenderFinding);
  guard.On("Bot", RenderVerdict);
}

document.querySelector(".actions")?.addEventListener("click", (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>("button[data-action]");
  const action = button?.dataset.action;
  if (!action) {
    return;
  }
  if (action === "toggle") {
    if (ActiveGuard.IsRunning()) {
      ActiveGuard.Stop();
    } else {
      ActiveGuard = BrowserGuard.Start(GuardConfig);
      Subscribe(ActiveGuard);
    }
    RenderStatus();
    return;
  }
  if (action === "catalog") {
    void LoadCatalog();
    return;
  }
  if (action === "clear") {
    if (List) {
      List.textContent = "";
    }
    return;
  }
  Simulations[action]?.();
});

Subscribe(ActiveGuard);
// Los hallazgos generados antes de suscribirse (p. ej. el baseline) se muestran también.
ActiveGuard.GetReport().Findings.forEach(RenderFinding);
RenderStatus();
RenderVerdict();
