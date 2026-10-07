import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { ResolveConfig } from "../src/Config/ResolveConfig";
import { RiskEngine } from "../src/Core/RiskEngine";
import { ScriptInjectionDetector } from "../src/Detectors/ScriptInjectionDetector";
import type { BrowserGuardConfig } from "../src/Types/BrowserGuardConfig";
import type { DomElementData, SecurityEvent } from "../src/Types/SecurityEvent";
import type { SecurityFinding } from "../src/Types/SecurityFinding";
import { FlushMicrotasks, FlushTasks, ResetGuard } from "./Helpers";

const Page = {
  GetPageOrigin: () => "https://app.example.com",
  GetPageProtocol: () => "https:",
};

function Script(data: Partial<DomElementData> = {}): DomElementData {
  return {
    TagName: "script",
    Src: "https://cdn.unknown.example/lib.js",
    Origin: "https://cdn.unknown.example",
    Scheme: "https:",
    Inline: false,
    ParserInserted: false,
    Integrity: "",
    ...data,
  };
}

function Evaluate(data: DomElementData, config: BrowserGuardConfig = {}): SecurityFinding | null {
  const resolved = ResolveConfig(config);
  const detector = new ScriptInjectionDetector(resolved, Page);
  const event: SecurityEvent<DomElementData> = {
    Id: "evt-1",
    Timestamp: 1,
    Type: "dom.element-inserted",
    Source: "Test",
    Data: data,
  };
  const candidate = detector.Analyze(event);
  return candidate
    ? new RiskEngine(resolved.Risk.Weights, "info").Evaluate(candidate, event)
    : null;
}

const KnownCdn = { Dom: { AllowedScriptOrigins: ["https://cdn.example.com"] } };

describe("ScriptInjectionDetector", () => {
  it("script externo conocido → info", () => {
    const finding = Evaluate(
      Script({ Src: "https://cdn.example.com/a.js", Origin: "https://cdn.example.com" }),
      KnownCdn,
    );
    expect(finding?.Severity).toBe("info");
    expect(finding?.Title).toBe("Known external script inserted");
  });

  it("script externo desconocido con integrity → medium", () => {
    const finding = Evaluate(Script({ Integrity: "sha384-abc" }));
    expect(finding?.Severity).toBe("medium");
    expect(finding?.Title).toBe("Unknown external script");
    expect(finding?.Evidence).toMatchObject({ Integrity: "present" });
  });

  it("script desconocido sin integrity → high", () => {
    const finding = Evaluate(Script());
    expect(finding?.Severity).toBe("high");
    expect(finding?.Signals).toContain("script.missing-integrity");
  });

  it("script desde origen bloqueado → critical", () => {
    const finding = Evaluate(Script(), {
      Network: { BlockedOrigins: ["https://cdn.unknown.example"] },
    });
    expect(finding?.Severity).toBe("critical");
    expect(finding?.Title).toBe("Script loaded from blocked origin");
  });

  it("script same-origin dinámico → info; insertado por el parser → sin hallazgo", () => {
    const sameOrigin = {
      Src: "https://app.example.com/chunk.js",
      Origin: "https://app.example.com",
    };
    expect(Evaluate(Script(sameOrigin))?.Severity).toBe("info");
    expect(Evaluate(Script({ ...sameOrigin, ParserInserted: true }))).toBeNull();
  });

  it("script inline dinámico → low, sin registrar contenido", () => {
    const finding = Evaluate(
      Script({ Src: null, Origin: null, Scheme: null, Inline: true, InlineLength: 120 }),
    );
    expect(finding?.Severity).toBe("low");
    expect(finding?.Evidence).toMatchObject({ Inline: true, InlineLength: 120 });
  });

  it("script inline del HTML original se ignora", () => {
    expect(
      Evaluate(
        Script({ Src: null, Origin: null, Scheme: null, Inline: true, ParserInserted: true }),
      ),
    ).toBeNull();
  });

  it("blob: se trata como contenido generado (inline)", () => {
    const finding = Evaluate(Script({ Src: "blob:[redacted]", Origin: null, Scheme: "blob:" }));
    expect(finding?.Signals).toContain("script.inline");
  });

  it("esquemas data: y javascript: son de riesgo alto", () => {
    const finding = Evaluate(Script({ Src: "data:[redacted]", Origin: null, Scheme: "data:" }));
    expect(finding?.Severity).toBe("high");
    expect(finding?.Title).toBe("Script with data: URL inserted");
  });

  it("fuentes no de red (extensiones) se reportan como info", () => {
    const finding = Evaluate(
      Script({ Src: "chrome-extension:[redacted]", Origin: null, Scheme: "chrome-extension:" }),
    );
    expect(finding?.Severity).toBe("info");
  });

  it("los pesos son configurables", () => {
    const finding = Evaluate(Script({ Integrity: "sha384-abc" }), {
      Risk: { Weights: { "script.unknown-origin": 0 } },
    });
    expect(finding?.Severity).toBe("info");
  });

  describe("iframe, object y embed", () => {
    const Frame = (data: Partial<DomElementData> = {}): DomElementData =>
      Script({ TagName: "iframe", Integrity: undefined, ...data });

    it("iframe dinámico a origen desconocido → medium", () => {
      const finding = Evaluate(Frame());
      expect(finding?.Category).toBe("dom");
      expect(finding?.Severity).toBe("medium");
    });

    it("iframe a origen permitido → info; en el HTML original → sin hallazgo", () => {
      const config = { Network: { AllowedOrigins: ["https://cdn.unknown.example"] } };
      expect(Evaluate(Frame(), config)?.Severity).toBe("info");
      expect(Evaluate(Frame({ ParserInserted: true }), config)).toBeNull();
    });

    it("iframe a origen bloqueado → critical", () => {
      const finding = Evaluate(Frame(), {
        Network: { BlockedOrigins: ["https://cdn.unknown.example"] },
      });
      expect(finding?.Severity).toBe("critical");
    });

    it("embed/object desconocido → high", () => {
      expect(Evaluate(Frame({ TagName: "embed" }))?.Severity).toBe("high");
      expect(Evaluate(Frame({ TagName: "object" }))?.Signals).toContain("dom.plugin-content");
    });

    it("iframe con javascript: → high", () => {
      const finding = Evaluate(
        Frame({ Src: "javascript:[redacted]", Origin: null, Scheme: "javascript:" }),
      );
      expect(finding?.Severity).toBe("high");
    });

    it("iframe srcdoc dinámico → info", () => {
      const finding = Evaluate(Frame({ Src: null, Origin: null, Scheme: null, Inline: true }));
      expect(finding?.Severity).toBe("info");
      expect(finding?.Description).toContain("inline");
    });
  });
});

describe("DomMonitor integrado", () => {
  afterEach(() => {
    ResetGuard();
    document.body.innerHTML = "";
  });

  async function WaitForObserver(): Promise<void> {
    await FlushTasks();
    await FlushMicrotasks();
  }

  function StartGuard(config: BrowserGuardConfig = {}): BrowserGuard {
    return BrowserGuard.Start({
      Console: false,
      Preset: "development",
      Monitors: { Fetch: false, Xhr: false, WebSocket: false, Prototype: false, Runtime: false },
      ...config,
    });
  }

  it("detecta un script externo insertado dinámicamente", async () => {
    const guard = StartGuard();
    const handler = vi.fn();
    guard.On("High", handler);

    const script = document.createElement("script");
    script.src = "https://evil.example/payload.js?k=1";
    script.async = true;
    document.head.appendChild(script);
    await WaitForObserver();

    expect(handler).toHaveBeenCalledTimes(1);
    const finding = handler.mock.calls[0]?.[0] as SecurityFinding;
    expect(finding.Evidence).toMatchObject({
      Src: "https://evil.example/payload.js",
      Async: true,
      Integrity: "missing",
    });
    script.remove();
  });

  it("detecta elementos dentro de subárboles insertados", async () => {
    const guard = StartGuard();
    const container = document.createElement("div");
    container.innerHTML =
      '<section><iframe src="https://frame.example/"></iframe><embed src="https://plugin.example/x"></section>';
    document.body.appendChild(container);
    await WaitForObserver();

    // El innerHTML también genera un hallazgo "xss" (contenido embebido): aquí se
    // verifican solo los elementos insertados que reporta DomMonitor.
    const tags = guard
      .GetReport()
      .Findings.filter((finding) => finding.Category === "dom")
      .map((finding) => (finding.Evidence as DomElementData).TagName);
    expect(tags).toEqual(["iframe", "embed"]);
  });

  it("no registra el contenido de scripts inline", async () => {
    const guard = StartGuard();
    const script = document.createElement("script");
    script.type = "text/plain";
    script.textContent = "const password = 'hunter2';";
    document.body.appendChild(script);
    await WaitForObserver();

    const report = JSON.stringify(guard.GetReport());
    expect(report).not.toContain("hunter2");
    expect(guard.GetReport().Findings[0]?.Evidence).toMatchObject({ InlineLength: 27 });
  });

  it("ignora otros elementos", async () => {
    const guard = StartGuard();
    document.body.appendChild(document.createElement("div"));
    await WaitForObserver();
    expect(guard.GetReport().Findings).toHaveLength(0);
  });

  it("Stop desconecta el MutationObserver", async () => {
    const guard = StartGuard();
    guard.Stop();
    const script = document.createElement("script");
    script.src = "https://evil.example/late.js";
    document.head.appendChild(script);
    await WaitForObserver();
    expect(guard.GetReport().Findings).toHaveLength(0);
    script.remove();
  });
});
