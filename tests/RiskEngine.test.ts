import { describe, expect, it } from "vitest";
import { RiskEngine } from "../src/Core/RiskEngine";
import type { FindingCandidate } from "../src/Types/Detector";
import type { SecurityEvent } from "../src/Types/SecurityEvent";

const Event: SecurityEvent = {
  Id: "evt-1",
  Timestamp: 1000,
  Type: "network.request",
  Source: "Test",
  Data: {},
  Stack: "submitPayment() Payment.ts:82:5",
};

function Candidate(overrides: Partial<FindingCandidate> = {}): FindingCandidate {
  return {
    Category: "network",
    Title: "Test",
    Description: "Test finding",
    Signals: ["network.unknown-origin"],
    ...overrides,
  };
}

describe("RiskEngine", () => {
  it("suma pesos de señales y limita a 0-100", () => {
    const engine = new RiskEngine();
    expect(engine.Score(["network.unknown-origin"])).toBe(45);
    expect(engine.Score(["network.blocked-origin", "network.unknown-origin"])).toBe(100);
    expect(engine.Score(["csp.report-only"])).toBe(0);
    expect(engine.Score([])).toBe(0);
  });

  it("ignora señales duplicadas", () => {
    const engine = new RiskEngine();
    expect(engine.Score(["script.dynamic", "script.dynamic"])).toBe(5);
  });

  it("traduce puntajes a severidad según umbrales", () => {
    const engine = new RiskEngine();
    expect(engine.SeverityForScore(0)).toBe("info");
    expect(engine.SeverityForScore(19)).toBe("info");
    expect(engine.SeverityForScore(20)).toBe("low");
    expect(engine.SeverityForScore(40)).toBe("medium");
    expect(engine.SeverityForScore(60)).toBe("high");
    expect(engine.SeverityForScore(80)).toBe("critical");
    expect(engine.SeverityForScore(100)).toBe("critical");
    expect(engine.SeverityForScore(-5)).toBe("info");
  });

  it("permite sobrescribir pesos", () => {
    const engine = new RiskEngine({ "network.unknown-origin": 85 });
    expect(engine.Assess(["network.unknown-origin"])).toEqual({
      RiskScore: 85,
      Severity: "critical",
    });
  });

  it("construye un hallazgo completo con stack y evidencia saneada", () => {
    const engine = new RiskEngine();
    const finding = engine.Evaluate(
      Candidate({ Evidence: { Origin: "https://x.example", Authorization: "Bearer abc" } }),
      Event,
    );
    expect(finding).not.toBeNull();
    expect(finding?.Severity).toBe("medium");
    expect(finding?.RiskScore).toBe(45);
    expect(finding?.EventId).toBe("evt-1");
    expect(finding?.Timestamp).toBe(1000);
    expect(finding?.Stack).toBe(Event.Stack);
    expect(finding?.Evidence).toEqual({ Origin: "https://x.example", Authorization: "[redacted]" });
  });

  it("omite evidencia y stack cuando no existen", () => {
    const engine = new RiskEngine();
    const finding = engine.Evaluate(Candidate(), { ...Event, Stack: undefined });
    expect(finding).not.toHaveProperty("Evidence");
    expect(finding).not.toHaveProperty("Stack");
  });

  it("descarta hallazgos bajo el umbral mínimo", () => {
    const engine = new RiskEngine({}, "high");
    expect(engine.Evaluate(Candidate(), Event)).toBeNull();
    expect(engine.ShouldReport("critical")).toBe(true);
    expect(engine.ShouldReport("medium")).toBe(false);
  });

  it("retorna peso 0 para señales desconocidas", () => {
    const engine = new RiskEngine();
    expect(engine.GetWeight("unknown" as never)).toBe(0);
  });
});
