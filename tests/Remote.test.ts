import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { RemoteReporting } from "../src/Plugins/RemoteReportingPlugin";
import { ResolveEndpoint } from "../src/Config/ConfigValidators";
import { RemoteLimits, ResolveRemoteConfig } from "../src/Config/ResolveRemoteConfig";
import { MaxBackoffMs, RemotePayloadSchema, RemoteReporter } from "../src/Reporters/RemoteReporter";
import type { RemotePayload } from "../src/Types/Remote";
import {
  IsRetryableStatus,
  KeepaliveLimitChars,
  RemoteTransport,
  type RemoteTransportLike,
  type TransportResult,
} from "../src/Reporters/RemoteTransport";
import type { Reporter } from "../src/Reporters/Reporter";
import type { ResolvedRemoteConfig } from "../src/Types/BrowserGuardConfig";
import type { SecurityFinding } from "../src/Types/SecurityFinding";
import type { Severity } from "../src/Types/Severity";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

const Page = "https://app.example.com/checkout?token=abc";

function Finding(
  id: number,
  severity: Severity = "medium",
  extra: Partial<SecurityFinding> = {},
): SecurityFinding {
  return {
    Id: `finding-${id}`,
    Timestamp: id,
    Category: "network",
    Severity: severity,
    Title: "Unknown outbound request",
    Description: "Test",
    RiskScore: 45,
    Signals: ["network.unknown-origin"],
    EventId: `evt-${id}`,
    Evidence: { Origin: "https://unknown.example" },
    Stack: "pay() Payment.ts:1:1",
    ...extra,
  };
}

function RemoteConfig(overrides: Partial<ResolvedRemoteConfig> = {}): ResolvedRemoteConfig {
  const resolved = ResolveRemoteConfig({ Endpoint: "https://collector.example/findings" }, Page);
  if (!resolved) {
    throw new Error("invalid test config");
  }
  return { ...resolved, ...overrides };
}

class FakeTransport implements RemoteTransportLike {
  public readonly Bodies: string[] = [];
  public readonly ExitBodies: string[] = [];
  public Results: TransportResult[] = [];
  public ExitAccepted = true;

  public Send(body: string): Promise<TransportResult> {
    this.Bodies.push(body);
    return Promise.resolve(this.Results.shift() ?? { Ok: true, Retryable: false, Status: 200 });
  }

  public SendOnExit(body: string): boolean {
    this.ExitBodies.push(body);
    return this.ExitAccepted;
  }

  public Payloads(): RemotePayload[] {
    return this.Bodies.map((body) => JSON.parse(body) as RemotePayload);
  }
}

describe("ResolveRemoteConfig", () => {
  it("sin configuración o sin endpoint, el envío remoto queda deshabilitado", () => {
    expect(ResolveRemoteConfig(undefined, Page)).toBeNull();
    expect(ResolveRemoteConfig({}, Page)).toBeNull();
  });

  it("valida el endpoint: https, mismo origen o localhost", () => {
    expect(ResolveEndpoint("https://collector.example/x#frag", Page)).toBe(
      "https://collector.example/x",
    );
    expect(ResolveEndpoint("/api/findings", Page)).toBe("https://app.example.com/api/findings");
    expect(ResolveEndpoint("http://localhost:8787/findings", Page)).toBe(
      "http://localhost:8787/findings",
    );
    expect(ResolveEndpoint("http://127.0.0.1:8787/", Page)).toBe("http://127.0.0.1:8787/");
    expect(ResolveEndpoint("http://collector.example/x", Page)).toBeNull();
    expect(ResolveEndpoint("javascript:alert(1)", Page)).toBeNull();
    expect(ResolveEndpoint("https://user:pass@collector.example/", Page)).toBeNull();
    expect(ResolveEndpoint("/relative", undefined)).toBeNull();
    expect(ResolveEndpoint(42, Page)).toBeNull();
  });

  it("aplica valores por defecto y límites", () => {
    const config = ResolveRemoteConfig(
      {
        Endpoint: "https://c.example",
        BatchSize: 1000,
        FlushIntervalMs: 1,
        MaxQueue: 1,
        MaxRetries: -2,
      },
      Page,
    );
    expect(config).toMatchObject({
      MinSeverity: "low",
      BatchSize: RemoteLimits.BatchSize.Max,
      FlushIntervalMs: RemoteLimits.FlushIntervalMs.Min,
      MaxQueue: RemoteLimits.MaxQueue.Min,
      MaxRetries: 0,
      IncludeStack: true,
      IncludeEvidence: true,
      IncludePagePath: true,
    });
  });

  it("filtra headers y metadatos inválidos", () => {
    const config = ResolveRemoteConfig(
      {
        Endpoint: "https://c.example",
        Headers: {
          "X-Ingest-Key": "public-key",
          "Bad Header": "x",
          "X-Inject": "a\r\nb",
          "X-Num": 1,
        },
        Metadata: {
          App: "shop",
          Version: 3,
          Beta: true,
          Nested: { a: 1 },
          Long: "x".repeat(500),
          Nan: Number.NaN,
        },
      },
      Page,
    );
    expect(config?.Headers).toEqual({ "X-Ingest-Key": "public-key" });
    expect(config?.Metadata).toEqual({
      App: "shop",
      Version: 3,
      Beta: true,
      Long: "x".repeat(RemoteLimits.MaxMetadataLength),
    });
  });
});

describe("RemoteReporter", () => {
  let transport: FakeTransport;
  const reporters: RemoteReporter[] = [];

  function Create(overrides: Partial<ResolvedRemoteConfig> = {}): RemoteReporter {
    const reporter = new RemoteReporter(RemoteConfig(overrides), transport, window);
    reporters.push(reporter);
    return reporter;
  }

  beforeEach(() => {
    vi.useFakeTimers();
    transport = new FakeTransport();
  });

  afterEach(() => {
    for (const reporter of reporters.splice(0)) {
      reporter.Dispose();
    }
    vi.useRealTimers();
  });

  it("envía un lote al alcanzar BatchSize", async () => {
    const reporter = Create({ BatchSize: 2 });
    reporter.Report(Finding(1));
    expect(transport.Bodies).toHaveLength(0);
    reporter.Report(Finding(2));
    await FlushMicrotasks();
    expect(transport.Payloads()[0]?.Findings.map((finding) => finding.Id)).toEqual([
      "finding-1",
      "finding-2",
    ]);
    expect(reporter.GetStats()).toEqual({ Queued: 0, Sent: 2, Dropped: 0, Failed: 0 });
  });

  it("envía un lote incompleto al vencer FlushIntervalMs y no deja timers ociosos", async () => {
    const reporter = Create({ FlushIntervalMs: 5000 });
    expect(vi.getTimerCount()).toBe(0);
    reporter.Report(Finding(1));
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(4999);
    expect(transport.Bodies).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(transport.Bodies).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("construye el payload con sesión, página sin query y metadatos", async () => {
    const reporter = Create({ BatchSize: 1, Metadata: { App: "shop" } });
    reporter.Report(Finding(1));
    await FlushMicrotasks();
    const [payload] = transport.Payloads();
    expect(payload).toMatchObject({
      Schema: RemotePayloadSchema,
      Page: { Origin: window.location.origin, Path: window.location.pathname },
      Metadata: { App: "shop" },
    });
    expect(payload?.SessionId).toEqual(expect.any(String));
    expect(payload?.Findings[0]).toMatchObject({
      Evidence: { Origin: "https://unknown.example" },
      Stack: "pay() Payment.ts:1:1",
    });
  });

  it("respeta IncludeStack, IncludeEvidence e IncludePagePath", async () => {
    const reporter = Create({
      BatchSize: 1,
      IncludeStack: false,
      IncludeEvidence: false,
      IncludePagePath: false,
    });
    reporter.Report(Finding(1));
    await FlushMicrotasks();
    const [payload] = transport.Payloads();
    expect(payload?.Page).toEqual({ Origin: window.location.origin });
    expect(payload?.Findings[0]).not.toHaveProperty("Stack");
    expect(payload?.Findings[0]).not.toHaveProperty("Evidence");
    expect(payload).not.toHaveProperty("Metadata");
  });

  it("filtra por severidad mínima", async () => {
    const reporter = Create({ BatchSize: 1, MinSeverity: "high" });
    reporter.Report(Finding(1, "medium"));
    reporter.Report(Finding(2, "critical"));
    await FlushMicrotasks();
    expect(
      transport.Payloads().flatMap((payload) => payload.Findings.map((finding) => finding.Id)),
    ).toEqual(["finding-2"]);
  });

  it("reintenta errores transitorios con backoff exponencial", async () => {
    transport.Results = [
      { Ok: false, Retryable: true, Status: 503 },
      { Ok: false, Retryable: true },
    ];
    const reporter = Create({ BatchSize: 1, FlushIntervalMs: 1000, MaxRetries: 3 });
    reporter.Report(Finding(1));
    await FlushMicrotasks();
    expect(reporter.GetStats().Queued).toBe(1);

    await vi.advanceTimersByTimeAsync(1999);
    expect(transport.Bodies).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(transport.Bodies).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(4000);
    expect(transport.Bodies).toHaveLength(3);
    expect(reporter.GetStats()).toEqual({ Queued: 0, Sent: 1, Dropped: 0, Failed: 0 });
  });

  it("descarta el lote al agotar los reintentos o ante errores no recuperables", async () => {
    transport.Results = [
      { Ok: false, Retryable: true },
      { Ok: false, Retryable: true },
      { Ok: false, Retryable: false, Status: 400 },
    ];
    const reporter = Create({ BatchSize: 1, FlushIntervalMs: 1000, MaxRetries: 1 });
    reporter.Report(Finding(1));
    await FlushMicrotasks();
    await vi.advanceTimersByTimeAsync(2000);
    expect(reporter.GetStats()).toMatchObject({ Queued: 0, Failed: 1 });

    reporter.Report(Finding(2));
    await FlushMicrotasks();
    expect(reporter.GetStats()).toMatchObject({ Queued: 0, Failed: 2 });
  });

  it("el backoff está limitado a MaxBackoffMs", async () => {
    transport.Results = Array.from({ length: 6 }, () => ({ Ok: false, Retryable: true }));
    const reporter = Create({ BatchSize: 1, FlushIntervalMs: 60_000, MaxRetries: 6 });
    reporter.Report(Finding(1));
    await FlushMicrotasks();
    await vi.advanceTimersByTimeAsync(MaxBackoffMs);
    expect(transport.Bodies).toHaveLength(2);
  });

  it("acota la cola descartando los hallazgos más antiguos", () => {
    const reporter = Create({ BatchSize: 100, MaxQueue: 10 });
    for (let i = 0; i < 15; i++) {
      reporter.Report(Finding(i));
    }
    expect(reporter.GetStats()).toMatchObject({ Queued: 10, Dropped: 5 });
  });

  it("divide lotes para respetar el límite de tamaño y recorta hallazgos enormes", async () => {
    const reporter = Create({ BatchSize: 100 });
    const big = "x".repeat(KeepaliveLimitChars / 3);
    for (let i = 0; i < 4; i++) {
      reporter.Report(Finding(i, "medium", { Description: big }));
    }
    reporter.Report(Finding(9, "medium", { Evidence: { Blob: "y".repeat(KeepaliveLimitChars) } }));
    reporter.Report(Finding(10, "medium", { Description: "z".repeat(KeepaliveLimitChars) }));
    await vi.advanceTimersByTimeAsync(5000);
    await vi.advanceTimersByTimeAsync(5000);
    await vi.advanceTimersByTimeAsync(5000);

    expect(transport.Bodies.every((body) => body.length <= KeepaliveLimitChars)).toBe(true);
    const sent = transport.Payloads().flatMap((payload) => payload.Findings);
    expect(sent.map((finding) => finding.Id)).toEqual([
      "finding-0",
      "finding-1",
      "finding-2",
      "finding-3",
      "finding-9",
    ]);
    expect(sent.at(-1)).not.toHaveProperty("Evidence");
    expect(reporter.GetStats()).toMatchObject({ Sent: 5, Dropped: 1 });
  });

  it("al ocultar la página envía la cola con SendOnExit", () => {
    const reporter = Create({ BatchSize: 50 });
    reporter.Report(Finding(1));
    reporter.Report(Finding(2));
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
    document.dispatchEvent(new Event("visibilitychange"));
    Reflect.deleteProperty(document, "visibilityState");

    expect(transport.ExitBodies).toHaveLength(1);
    expect(reporter.GetStats()).toMatchObject({ Queued: 0, Sent: 2 });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("pagehide también vacía la cola y los rechazos se cuentan como fallidos", () => {
    transport.ExitAccepted = false;
    const reporter = Create();
    reporter.Report(Finding(1));
    window.dispatchEvent(new Event("pagehide"));
    expect(reporter.GetStats()).toMatchObject({ Queued: 0, Failed: 1 });
  });

  it("Dispose envía lo pendiente, quita listeners y deja de aceptar hallazgos", () => {
    const reporter = Create();
    reporter.Report(Finding(1));
    reporter.Dispose();
    expect(transport.ExitBodies).toHaveLength(1);

    reporter.Report(Finding(2));
    window.dispatchEvent(new Event("pagehide"));
    expect(transport.ExitBodies).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("RemoteTransport", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("clasifica estados reintentables", () => {
    expect([408, 429, 500, 503].every(IsRetryableStatus)).toBe(true);
    expect([400, 401, 404, 413].some(IsRetryableStatus)).toBe(false);
  });

  it("envía con keepalive, sin cookies ni referrer y con headers propios", async () => {
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true, status: 204 }));
    const fakeWindow = { fetch: fetchMock, navigator: {} } as unknown as Window & typeof globalThis;
    const transport = new RemoteTransport("https://c.example/f", { "X-Key": "k" }, fakeWindow);

    await expect(transport.Send("{}")).resolves.toEqual({
      Ok: true,
      Retryable: false,
      Status: 204,
    });
    expect(fetchMock).toHaveBeenCalledWith("https://c.example/f", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Key": "k" },
      body: "{}",
      keepalive: true,
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
  });

  it("errores HTTP y de red", async () => {
    const statuses = [
      { ok: false, status: 503 },
      { ok: false, status: 400 },
    ];
    const fetchMock = vi.fn(() => {
      const next = statuses.shift();
      return next ? Promise.resolve(next) : Promise.reject(new TypeError("network"));
    });
    const transport = new RemoteTransport("https://c.example", {}, {
      fetch: fetchMock,
      navigator: {},
    } as unknown as Window & typeof globalThis);
    await expect(transport.Send("{}")).resolves.toMatchObject({ Ok: false, Retryable: true });
    await expect(transport.Send("{}")).resolves.toMatchObject({ Ok: false, Retryable: false });
    await expect(transport.Send("{}")).resolves.toEqual({ Ok: false, Retryable: true });
  });

  it("sin fetch no envía", async () => {
    const transport = new RemoteTransport("https://c.example", {}, {
      navigator: {},
    } as unknown as Window & typeof globalThis);
    await expect(transport.Send("{}")).resolves.toEqual({ Ok: false, Retryable: false });
    expect(transport.SendOnExit("{}")).toBe(false);
  });

  it("SendOnExit usa sendBeacon sin headers y fetch keepalive con headers", () => {
    const beacon = vi.fn(() => true);
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true, status: 200 }));
    const fakeWindow = {
      fetch: fetchMock,
      navigator: { sendBeacon: beacon },
    } as unknown as Window & typeof globalThis;

    expect(new RemoteTransport("https://c.example", {}, fakeWindow).SendOnExit("{}")).toBe(true);
    expect(beacon).toHaveBeenCalledWith("https://c.example", expect.any(Blob));
    expect(fetchMock).not.toHaveBeenCalled();

    expect(
      new RemoteTransport("https://c.example", { "X-Key": "k" }, fakeWindow).SendOnExit("{}"),
    ).toBe(true);
    expect(beacon).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("si sendBeacon rechaza el envío, recurre a fetch", () => {
    const fetchMock = vi.fn(() => Promise.reject(new Error("x")));
    const fakeWindow = {
      fetch: fetchMock,
      navigator: { sendBeacon: () => false },
    } as unknown as Window & typeof globalThis;
    expect(new RemoteTransport("https://c.example", {}, fakeWindow).SendOnExit("{}")).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("Envío remoto integrado", () => {
  afterEach(() => {
    ResetGuard();
  });

  const NetworkOnly = {
    Console: "silent",
    Monitors: {
      Xhr: false,
      WebSocket: false,
      Dom: false,
      Csp: false,
      Prototype: false,
      Runtime: false,
    },
  } as const;

  it("los envíos propios usan el fetch original y no generan hallazgos", async () => {
    const original = vi.fn(() => Promise.resolve({ ok: true, status: 200 }));
    window.fetch = original as unknown as typeof window.fetch;
    const guard = BrowserGuard.Start({
      ...NetworkOnly,
      Plugins: [RemoteReporting({ Endpoint: "http://localhost:8787/findings", BatchSize: 1 })],
    });

    await window.fetch("https://unknown.example/collect");
    await FlushMicrotasks();
    await FlushMicrotasks();

    expect(original).toHaveBeenCalledWith(
      "http://localhost:8787/findings",
      expect.objectContaining({ method: "POST" }),
    );
    expect(guard.GetReport().Statistics.Total).toBe(1);
    expect(guard.GetStatus().Remote).toEqual({ Queued: 0, Sent: 1, Dropped: 0, Failed: 0 });
  });

  it("sin Remote, GetStatus().Remote es null", () => {
    expect(BrowserGuard.Start(NetworkOnly).GetStatus().Remote).toBeNull();
  });

  it("acepta reporters propios y los libera en Stop", async () => {
    window.fetch = vi.fn(() => Promise.resolve(null)) as unknown as typeof window.fetch;
    const custom: Reporter = { Name: "Siem", Report: vi.fn(), Dispose: vi.fn() };
    const guard = BrowserGuard.Start({
      ...NetworkOnly,
      Reporters: [custom, null as unknown as Reporter, {} as Reporter],
    });
    await window.fetch("https://unknown.example/collect");
    await FlushMicrotasks();
    expect(custom.Report).toHaveBeenCalledTimes(1);
    expect(() => guard.GetConfig()).not.toThrow();
    guard.Stop();
    expect(custom.Dispose).toHaveBeenCalledTimes(1);
  });
});
