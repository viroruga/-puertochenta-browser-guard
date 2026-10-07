import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { ResolveConfig } from "../src/Config/ResolveConfig";
import { RiskEngine } from "../src/Core/RiskEngine";
import { CspViolationDetector } from "../src/Detectors/CspViolationDetector";
import type { CspViolationData, SecurityEvent } from "../src/Types/SecurityEvent";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

/**
 * jsdom no implementa CSP ni SecurityPolicyViolationEvent. Se despacha un Event
 * genérico con las mismas propiedades para verificar la captura y el análisis;
 * la generación real de violaciones solo puede probarse en un navegador (ver demo).
 */
function DispatchViolation(properties: Partial<Record<string, string | number>>): void {
  const event = new Event("securitypolicyviolation", { bubbles: true });
  for (const [key, value] of Object.entries(properties)) {
    Object.defineProperty(event, key, { value });
  }
  document.dispatchEvent(event);
}

function Violation(data: Partial<CspViolationData> = {}): CspViolationData {
  return {
    BlockedUri: "https://evil.example/x.js",
    BlockedOrigin: "https://evil.example",
    ViolatedDirective: "script-src-elem",
    EffectiveDirective: "script-src-elem",
    SourceFile: "https://app.example.com/main.js",
    LineNumber: 10,
    ColumnNumber: 5,
    Disposition: "enforce",
    ...data,
  };
}

function Evaluate(
  data: CspViolationData,
  blocked: string[] = [],
): ReturnType<RiskEngine["Evaluate"]> {
  const config = ResolveConfig({ Network: { BlockedOrigins: blocked } });
  const event: SecurityEvent<CspViolationData> = {
    Id: "evt-1",
    Timestamp: 1,
    Type: "csp.violation",
    Source: "Test",
    Data: data,
  };
  return new RiskEngine({}, "info").Evaluate(
    new CspViolationDetector(config).Analyze(event),
    event,
  );
}

describe("CspViolationDetector", () => {
  it("violación de script → medium", () => {
    const finding = Evaluate(Violation());
    expect(finding?.Category).toBe("csp");
    expect(finding?.Severity).toBe("medium");
    expect(finding?.Title).toBe("CSP violation: script-src-elem");
  });

  it("violación no relacionada con scripts → low", () => {
    const finding = Evaluate(
      Violation({ EffectiveDirective: "img-src", ViolatedDirective: "img-src" }),
    );
    expect(finding?.Severity).toBe("low");
  });

  it("report-only reduce el riesgo", () => {
    const finding = Evaluate(Violation({ Disposition: "report" }));
    expect(finding?.RiskScore).toBe(45);
    expect(finding?.Description).toContain("report-only");
  });

  it("origen bloqueado eleva a critical", () => {
    const finding = Evaluate(Violation(), ["https://evil.example"]);
    expect(finding?.Severity).toBe("critical");
  });

  it("usa la directiva violada si falta la efectiva", () => {
    const finding = Evaluate(Violation({ EffectiveDirective: "", ViolatedDirective: "" }));
    expect(finding?.Title).toBe("CSP violation: unknown directive");
  });
});

describe("CspMonitor", () => {
  afterEach(() => {
    ResetGuard();
  });

  function StartGuard(): BrowserGuard {
    return BrowserGuard.Start({
      Console: false,
      Preset: "forensic",
      Monitors: {
        Fetch: false,
        Xhr: false,
        WebSocket: false,
        Dom: false,
        Prototype: false,
        Runtime: false,
      },
    });
  }

  it("captura la violación con todos los campos y la URL saneada", async () => {
    const guard = StartGuard();
    const handler = vi.fn();
    guard.On("Finding", handler);

    DispatchViolation({
      blockedURI: "https://evil.example/steal.js?token=abc",
      violatedDirective: "script-src-elem",
      effectiveDirective: "script-src-elem",
      sourceFile: "https://localhost:3000/app.js?v=1",
      lineNumber: 82,
      columnNumber: 7,
      disposition: "enforce",
    });
    await FlushMicrotasks();

    const [event] = guard.GetTimeline();
    expect(event?.Type).toBe("csp.violation");
    expect(event?.Data).toEqual({
      BlockedUri: "https://evil.example/steal.js",
      BlockedOrigin: "https://evil.example",
      ViolatedDirective: "script-src-elem",
      EffectiveDirective: "script-src-elem",
      SourceFile: "https://localhost:3000/app.js",
      LineNumber: 82,
      ColumnNumber: 7,
      Disposition: "enforce",
    });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("acepta palabras clave como blockedURI y aplica valores por defecto", async () => {
    const guard = StartGuard();
    DispatchViolation({ blockedURI: "inline", effectiveDirective: "script-src" });
    await FlushMicrotasks();
    expect(guard.GetTimeline()[0]?.Data).toMatchObject({
      BlockedUri: "inline",
      BlockedOrigin: null,
      SourceFile: "",
      LineNumber: 0,
      Disposition: "enforce",
    });
  });

  it("captura aunque la aplicación detenga la propagación", async () => {
    const guard = StartGuard();
    const stopper = (event: Event): void => {
      event.stopPropagation();
    };
    document.body.addEventListener("securitypolicyviolation", stopper);
    const event = new Event("securitypolicyviolation", { bubbles: true });
    document.body.dispatchEvent(event);
    await FlushMicrotasks();
    expect(guard.GetTimeline()).toHaveLength(1);
    document.body.removeEventListener("securitypolicyviolation", stopper);
  });

  it("Stop remueve el listener", async () => {
    const guard = StartGuard();
    guard.Stop();
    DispatchViolation({ blockedURI: "eval" });
    await FlushMicrotasks();
    expect(guard.GetTimeline()).toHaveLength(0);
  });
});
