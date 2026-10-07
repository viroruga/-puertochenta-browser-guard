import { describe, expect, it, vi } from "vitest";
import { ConsoleReporter, DedupeWindowMs } from "../src/Reporters/ConsoleReporter";
import type { SecurityFinding } from "../src/Types/SecurityFinding";
import type { Severity } from "../src/Types/Severity";

function CreateConsole() {
  return {
    group: vi.fn(),
    groupCollapsed: vi.fn(),
    groupEnd: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
  };
}

function Finding(severity: Severity, overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    Id: "finding-1",
    Timestamp: 1,
    Category: "network",
    Severity: severity,
    Title: "Unknown outbound request",
    Description: "A fetch request targeted https://unknown.example.",
    RiskScore: 82,
    Signals: ["network.unknown-origin"],
    EventId: "evt-1",
    Evidence: { Origin: "https://unknown.example" },
    Stack: "submitPayment() Payment.ts:82:5",
    ...overrides,
  };
}

describe("ConsoleReporter", () => {
  it("imprime el formato profesional con banner, categoría, origen, riesgo y stack", () => {
    const output = CreateConsole();
    new ConsoleReporter("info", output).Report(Finding("high"));

    const text = output.error.mock.calls[0]?.[0] as string;
    expect(text).toContain("║ BrowserGuard");
    expect(text).toContain("HIGH SECURITY EVENT");
    expect(text).toContain("Category:\nnetwork");
    expect(text).toContain("Unknown outbound request");
    expect(text).toContain("Origin:\nhttps://unknown.example");
    expect(text).toContain("Risk:\n82 / 100");
    expect(text).toContain("Stack:\nsubmitPayment() Payment.ts:82:5");
    expect(output.error).toHaveBeenCalledWith("Evidence:", { Origin: "https://unknown.example" });
  });

  it.each([
    ["critical", "group", "error"],
    ["high", "group", "error"],
    ["medium", "groupCollapsed", "warn"],
    ["low", "groupCollapsed", "info"],
    ["info", "groupCollapsed", "info"],
  ] as const)("%s usa console.%s y console.%s", (severity, groupMethod, writeMethod) => {
    const output = CreateConsole();
    new ConsoleReporter("info", output).Report(Finding(severity));
    expect(output[groupMethod]).toHaveBeenCalledTimes(1);
    expect(output[writeMethod]).toHaveBeenCalled();
    expect(output.groupEnd).toHaveBeenCalledTimes(1);
  });

  it("respeta el umbral de severidad", () => {
    const output = CreateConsole();
    const reporter = new ConsoleReporter("medium", output);
    reporter.Report(Finding("low"));
    reporter.Report(Finding("info"));
    expect(output.groupCollapsed).not.toHaveBeenCalled();
    reporter.Report(Finding("medium"));
    expect(output.groupCollapsed).toHaveBeenCalledTimes(1);
  });

  it("omite secciones opcionales ausentes", () => {
    const output = CreateConsole();
    new ConsoleReporter("info", output).Report(
      Finding("medium", { Evidence: undefined, Stack: undefined }),
    );
    const text = output.warn.mock.calls[0]?.[0] as string;
    expect(text).not.toContain("Origin:");
    expect(text).not.toContain("Stack:");
    expect(output.warn).toHaveBeenCalledTimes(1);
  });

  it("suprime duplicados dentro de la ventana e informa la cantidad omitida", () => {
    const output = CreateConsole();
    let now = 0;
    const reporter = new ConsoleReporter("info", output, () => now);

    reporter.Report(Finding("medium"));
    now = 1000;
    reporter.Report(Finding("medium"));
    reporter.Report(Finding("medium"));
    expect(output.groupCollapsed).toHaveBeenCalledTimes(1);

    now = DedupeWindowMs + 1;
    reporter.Report(Finding("medium"));
    expect(output.groupCollapsed).toHaveBeenCalledTimes(2);
    const text = output.warn.mock.calls.at(-2)?.[0] as string;
    expect(text).toContain("2 similar event(s) suppressed");
  });

  it("hallazgos con distinto origen no se deduplican", () => {
    const output = CreateConsole();
    const reporter = new ConsoleReporter("info", output, () => 0);
    reporter.Report(Finding("medium"));
    reporter.Report(Finding("medium", { Evidence: { Origin: "https://other.example" } }));
    expect(output.groupCollapsed).toHaveBeenCalledTimes(2);
  });

  it("la memoria de deduplicación está acotada", () => {
    const output = CreateConsole();
    const reporter = new ConsoleReporter("info", output, () => 0);
    for (let i = 0; i < 250; i++) {
      reporter.Report(Finding("info", { Evidence: { Origin: `https://o${i}.example` } }));
    }
    // La primera clave fue descartada: vuelve a imprimirse.
    reporter.Report(Finding("info", { Evidence: { Origin: "https://o0.example" } }));
    expect(output.groupCollapsed).toHaveBeenCalledTimes(251);
  });

  it("Dispose limpia el estado de deduplicación", () => {
    const output = CreateConsole();
    const reporter = new ConsoleReporter("info", output, () => 0);
    reporter.Report(Finding("medium"));
    reporter.Dispose();
    reporter.Report(Finding("medium"));
    expect(output.groupCollapsed).toHaveBeenCalledTimes(2);
  });

  it("cierra el grupo aunque la escritura falle", () => {
    const output = CreateConsole();
    output.error.mockImplementation(() => {
      throw new Error("console broken");
    });
    expect(() => {
      new ConsoleReporter("info", output).Report(Finding("critical"));
    }).toThrow();
    expect(output.groupEnd).toHaveBeenCalledTimes(1);
  });
});
