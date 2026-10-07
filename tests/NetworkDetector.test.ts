import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { ResolveConfig } from "../src/Config/ResolveConfig";
import { RiskEngine } from "../src/Core/RiskEngine";
import { NetworkDetector } from "../src/Detectors/NetworkDetector";
import type { BrowserGuardConfig } from "../src/Types/BrowserGuardConfig";
import type { NetworkRequestData, SecurityEvent } from "../src/Types/SecurityEvent";
import type { SecurityFinding } from "../src/Types/SecurityFinding";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

const Page = {
  GetPageOrigin: () => "https://app.example.com",
  GetPageProtocol: () => "https:",
};

function CreateEvent(data: Partial<NetworkRequestData>): SecurityEvent<NetworkRequestData> {
  return {
    Id: "evt-1",
    Timestamp: 1,
    Type: "network.request",
    Source: "Test",
    Data: {
      Transport: "fetch",
      Url: "https://unknown.example/collect",
      Origin: "https://unknown.example",
      Method: "POST",
      HasQuery: false,
      QueryLength: 0,
      ...data,
    },
  };
}

function Evaluate(
  data: Partial<NetworkRequestData>,
  config: BrowserGuardConfig = {},
): SecurityFinding | null {
  const resolved = ResolveConfig({ Risk: { MinSeverity: "info" }, ...config });
  const detector = new NetworkDetector(resolved, Page);
  const event = CreateEvent(data);
  const candidate = detector.Analyze(event);
  return candidate
    ? new RiskEngine(resolved.Risk.Weights, "info").Evaluate(candidate, event)
    : null;
}

describe("NetworkDetector", () => {
  it("same-origin es normal", () => {
    expect(
      Evaluate({ Url: "https://app.example.com/api", Origin: "https://app.example.com" }),
    ).toBeNull();
  });

  it("AllowedOrigins es normal, incluyendo comodines", () => {
    const config = {
      Network: { AllowedOrigins: ["https://api.example.com", "https://*.cdn.example.net"] },
    };
    expect(Evaluate({ Origin: "https://api.example.com" }, config)).toBeNull();
    expect(Evaluate({ Origin: "https://eu.cdn.example.net" }, config)).toBeNull();
  });

  it("origen externo desconocido es medium", () => {
    const finding = Evaluate({});
    expect(finding?.Severity).toBe("medium");
    expect(finding?.Category).toBe("network");
    expect(finding?.Title).toBe("Unknown outbound request");
    expect(finding?.Evidence).toMatchObject({
      Origin: "https://unknown.example",
      Method: "POST",
      Classification: "unknown",
    });
  });

  it("BlockedOrigins es critical y tiene prioridad sobre AllowedOrigins", () => {
    const finding = Evaluate(
      {},
      {
        Network: {
          AllowedOrigins: ["https://unknown.example"],
          BlockedOrigins: ["https://unknown.example"],
        },
      },
    );
    expect(finding?.Severity).toBe("critical");
    expect(finding?.Signals).toEqual(["network.blocked-origin"]);
  });

  it("WebSocket hacia el mismo host se considera same-origin", () => {
    expect(
      Evaluate({
        Transport: "websocket",
        Url: "wss://app.example.com/ws",
        Origin: "wss://app.example.com",
      }),
    ).toBeNull();
  });

  it("WebSocket desconocido suma riesgo y conserva protocolos", () => {
    const finding = Evaluate({
      Transport: "websocket",
      Url: "wss://socket.example/live",
      Origin: "wss://socket.example",
      Method: undefined,
      Protocols: ["chat"],
    });
    expect(finding?.Title).toBe("WebSocket connection to unknown origin");
    expect(finding?.Severity).toBe("medium");
    expect(finding?.RiskScore).toBe(55);
    expect(finding?.Evidence).toMatchObject({ Protocols: ["chat"] });
    expect(finding?.Evidence).not.toHaveProperty("Method");
  });

  it("transporte no cifrado desde una página https eleva a high", () => {
    const finding = Evaluate({ Url: "http://plain.example/x", Origin: "http://plain.example" });
    expect(finding?.Severity).toBe("high");
    expect(finding?.Signals).toContain("network.insecure-transport");
  });

  it("URLs sin origen de red (data:, blob:) se ignoran", () => {
    expect(Evaluate({ Url: "data:[redacted]", Origin: null })).toBeNull();
  });
});

describe("NetworkDetector integrado", () => {
  afterEach(() => {
    ResetGuard();
  });

  it("emite Threat, Medium y Finding para una solicitud desconocida", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const guard = BrowserGuard.Start({
      Console: false,
      Monitors: { Prototype: false, Runtime: false },
    });
    const threat = vi.fn();
    const medium = vi.fn();
    const critical = vi.fn();
    guard.On("Threat", threat);
    guard.On("Medium", medium);
    guard.On("Critical", critical);

    await window.fetch("https://unknown.example/collect");
    await window.fetch("/same-origin");
    await FlushMicrotasks();

    expect(threat).toHaveBeenCalledTimes(1);
    expect(medium).toHaveBeenCalledTimes(1);
    expect(critical).not.toHaveBeenCalled();
    const report = guard.GetReport();
    expect(report.Statistics).toMatchObject({ Total: 1, Medium: 1 });
    expect(Object.isFrozen(report.Findings[0])).toBe(true);
  });
});
