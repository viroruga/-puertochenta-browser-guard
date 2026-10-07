import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { FindingHistory } from "../src/Core/FindingHistory";
import type { SecurityFinding } from "../src/Types/SecurityFinding";
import type { Severity } from "../src/Types/Severity";
import { RingBuffer } from "../src/Utils/RingBuffer";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

function Finding(id: number, severity: Severity = "medium"): SecurityFinding {
  return {
    Id: `finding-${id}`,
    Timestamp: id,
    Category: "network",
    Severity: severity,
    Title: "Test",
    Description: "Test",
    RiskScore: 50,
    Signals: [],
    EventId: `evt-${id}`,
  };
}

describe("RingBuffer", () => {
  it("conserva el orden cronológico y descarta los más antiguos", () => {
    const buffer = new RingBuffer<number>(3);
    for (const value of [1, 2, 3, 4, 5]) {
      buffer.Push(value);
    }
    expect(buffer.ToArray()).toEqual([3, 4, 5]);
    expect(buffer.Size).toBe(3);
  });

  it("Clear vacía el buffer", () => {
    const buffer = new RingBuffer<number>(2);
    buffer.Push(1);
    buffer.Clear();
    expect(buffer.ToArray()).toEqual([]);
    expect(buffer.Size).toBe(0);
  });

  it("rechaza capacidades inválidas", () => {
    expect(() => new RingBuffer(0)).toThrow(RangeError);
    expect(() => new RingBuffer(1.5)).toThrow(RangeError);
  });
});

describe("FindingHistory", () => {
  it("limita los hallazgos almacenados pero acumula estadísticas", () => {
    const history = new FindingHistory(2);
    history.Add(Finding(1, "critical"));
    history.Add(Finding(2, "high"));
    history.Add(Finding(3, "info"));
    history.Add(Finding(4, "low"));
    history.Add(Finding(5, "medium"));

    expect(history.GetFindings().map((finding) => finding.Id)).toEqual(["finding-4", "finding-5"]);
    expect(history.Size).toBe(2);
    expect(history.GetStatistics()).toEqual({
      Total: 5,
      Critical: 1,
      High: 1,
      Medium: 1,
      Low: 1,
      Info: 1,
    });
  });

  it("retorna copias de las estadísticas", () => {
    const history = new FindingHistory(10);
    const stats = history.GetStatistics();
    stats.Total = 99;
    expect(history.GetStatistics().Total).toBe(0);
  });
});

describe("Historial y modo forense integrados", () => {
  afterEach(() => {
    ResetGuard();
  });

  const NetworkOnly = {
    Console: false,
    Monitors: {
      Xhr: false,
      WebSocket: false,
      Dom: false,
      Csp: false,
      Prototype: false,
      Runtime: false,
    },
  } as const;

  async function FetchMany(count: number): Promise<void> {
    for (let i = 0; i < count; i++) {
      await window.fetch(`https://unknown${i}.example/x`);
    }
    await FlushMicrotasks();
  }

  it("History.MaxFindings limita el historial", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const guard = BrowserGuard.Start({ ...NetworkOnly, History: { MaxFindings: 10 } });
    await FetchMany(15);
    const report = guard.GetReport();
    expect(report.Findings).toHaveLength(10);
    expect(report.Statistics.Total).toBe(15);
    expect(guard.GetStatus().FindingsCount).toBe(10);
  });

  it("sin modo forense no se guarda línea de tiempo", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const guard = BrowserGuard.Start(NetworkOnly);
    await FetchMany(2);
    expect(guard.GetTimeline()).toEqual([]);
    expect(guard.GetStatus().TimelineSize).toBe(0);
  });

  it("el modo forense guarda eventos (incluso normales) en un ring buffer acotado", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const guard = BrowserGuard.Start({
      ...NetworkOnly,
      Preset: "forensic",
      Forensic: { MaxEvents: 10 },
    });
    await window.fetch("/same-origin");
    await FetchMany(12);

    const timeline = guard.GetTimeline();
    expect(timeline).toHaveLength(10);
    expect(BrowserGuard.GetTimeline()).toHaveLength(10);
    expect(guard.GetStatus().TimelineSize).toBe(10);
    // El evento same-origin fue el primero y quedó fuera del buffer.
    expect(timeline.some((event) => JSON.stringify(event.Data).includes("same-origin"))).toBe(
      false,
    );
  });

  it("el historial sigue disponible después de Stop", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const guard = BrowserGuard.Start(NetworkOnly);
    await FetchMany(1);
    guard.Stop();
    expect(guard.GetReport().Findings).toHaveLength(1);
  });

  it("Stop procesa los eventos capturados justo antes de detener", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const guard = BrowserGuard.Start(NetworkOnly);
    void window.fetch("https://late.example/x");
    guard.Stop();
    await FlushMicrotasks();
    expect(guard.GetReport().Findings).toHaveLength(1);
  });

  it("errores en manejadores de la aplicación no interrumpen a BrowserGuard", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const reportError = vi.fn();
    vi.stubGlobal("reportError", reportError);
    const guard = BrowserGuard.Start(NetworkOnly);
    const after = vi.fn();
    guard.On("Finding", () => {
      throw new Error("app bug");
    });
    guard.On("Finding", after);
    await FetchMany(1);
    expect(after).toHaveBeenCalledTimes(1);
    expect(reportError).toHaveBeenCalledWith(expect.objectContaining({ message: "app bug" }));
    vi.unstubAllGlobals();
  });

  it("Once y Off sobre la instancia", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const guard = BrowserGuard.Start(NetworkOnly);
    const once = vi.fn();
    const removed = vi.fn();
    guard.Once("Threat", once);
    BrowserGuard.On("Threat", removed);
    BrowserGuard.Off("Threat", removed);
    await FetchMany(2);
    expect(once).toHaveBeenCalledTimes(1);
    expect(removed).not.toHaveBeenCalled();
  });

  it("ConsoleReporter se activa con Console: true y respeta el preset", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const groupCollapsed = vi.spyOn(console, "groupCollapsed").mockImplementation(() => undefined);
    vi.spyOn(console, "groupEnd").mockImplementation(() => undefined);
    BrowserGuard.Start({ ...NetworkOnly, Console: true });
    await FetchMany(1);
    expect(groupCollapsed).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalled();
  });
});
