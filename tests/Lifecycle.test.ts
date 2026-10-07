import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { ResolveConfig } from "../src/Config/ResolveConfig";
import { GuardContext, MaxPendingEvents } from "../src/Core/GuardContext";
import { MonitorRegistry } from "../src/Core/MonitorRegistry";
import type { Monitor } from "../src/Types/Monitor";
import { FlushMicrotasks, ResetGuard } from "./Helpers";

describe("Stop restaura el entorno completo", () => {
  afterEach(() => {
    ResetGuard();
    vi.useRealTimers();
  });

  it("todas las funciones interceptadas vuelven a su referencia original", () => {
    window.fetch = vi.fn();
    const before = {
      fetch: window.fetch,
      open: XMLHttpRequest.prototype.open,
      send: XMLHttpRequest.prototype.send,
      WebSocket: window.WebSocket,
    };

    const guard = BrowserGuard.Start({ Console: false, Preset: "strict" });
    expect(guard.GetStatus().Monitors.every((monitor) => monitor.Running)).toBe(true);
    expect(window.fetch).not.toBe(before.fetch);
    expect(XMLHttpRequest.prototype.open).not.toBe(before.open);
    expect(XMLHttpRequest.prototype.send).not.toBe(before.send);
    expect(window.WebSocket).not.toBe(before.WebSocket);

    guard.Stop();
    expect(window.fetch).toBe(before.fetch);
    expect(XMLHttpRequest.prototype.open).toBe(before.open);
    expect(XMLHttpRequest.prototype.send).toBe(before.send);
    expect(window.WebSocket).toBe(before.WebSocket);
    expect(guard.GetStatus().Monitors.every((monitor) => !monitor.Running)).toBe(true);
  });

  it("no quedan timers, listeners ni observers activos", async () => {
    vi.useFakeTimers();
    const addListener = vi.spyOn(document, "addEventListener");
    const removeListener = vi.spyOn(document, "removeEventListener");
    const disconnect = vi.spyOn(MutationObserver.prototype, "disconnect");

    const guard = BrowserGuard.Start({ Console: false });
    expect(vi.getTimerCount()).toBeGreaterThan(0);
    guard.Stop();
    // Stop procesa los eventos pendientes (en jsdom, el baseline de runtime); luego nada más.
    const findingsAtStop = guard.GetReport().Statistics.Total;

    expect(vi.getTimerCount()).toBe(0);
    expect(disconnect).toHaveBeenCalled();
    const added = addListener.mock.calls.filter(([type]) => type === "securitypolicyviolation");
    const removed = removeListener.mock.calls.filter(
      ([type]) => type === "securitypolicyviolation",
    );
    expect(added).toHaveLength(1);
    expect(removed).toHaveLength(1);
    expect(removed[0]?.[1]).toBe(added[0]?.[1]);

    // Después de Stop no se generan hallazgos.
    const script = document.createElement("script");
    script.src = "https://evil.example/x.js";
    document.head.appendChild(script);
    await FlushMicrotasks();
    expect(guard.GetReport().Statistics.Total).toBe(findingsAtStop);
    script.remove();
  });

  it("Start/Stop repetidos no acumulan interceptores", async () => {
    const original = vi.fn(() => Promise.resolve(null));
    window.fetch = original as unknown as typeof window.fetch;
    for (let i = 0; i < 5; i++) {
      BrowserGuard.Start({ Console: false });
      BrowserGuard.Stop();
    }
    expect(window.fetch).toBe(original);

    const guard = BrowserGuard.Start({ Console: false, Monitors: { Runtime: false } });
    await window.fetch("https://unknown.example");
    await FlushMicrotasks();
    expect(guard.GetReport().Statistics.Total).toBe(1);
  });

  it("monitores deshabilitados no se registran", () => {
    const guard = BrowserGuard.Start({
      Console: false,
      Monitors: {
        Fetch: false,
        Xhr: false,
        WebSocket: false,
        Dom: false,
        Csp: false,
        Prototype: false,
        Runtime: false,
        Sinks: false,
        Channels: false,
        Realms: false,
      },
    });
    expect(guard.GetStatus().Monitors).toEqual([]);
  });
});

describe("GuardContext", () => {
  it("descarta eventos ante una ráfaga para no crecer sin límite", () => {
    const dispatched: unknown[] = [];
    const context = new GuardContext(ResolveConfig(), window, (event) => dispatched.push(event));
    const data = {
      Transport: "fetch",
      Url: "x",
      Origin: null,
      HasQuery: false,
      QueryLength: 0,
    } as const;
    for (let i = 0; i < MaxPendingEvents + 5; i++) {
      context.Emit("network.request", "Test", data);
    }
    expect(context.DroppedEvents).toBe(5);
    context.Flush();
    expect(dispatched).toHaveLength(MaxPendingEvents);
  });

  it("los errores al despachar se contabilizan sin propagarse", () => {
    const context = new GuardContext(ResolveConfig(), window, () => {
      throw new Error("detector bug");
    });
    context.Emit("csp.violation", "Test", {
      BlockedUri: "",
      BlockedOrigin: null,
      ViolatedDirective: "",
      EffectiveDirective: "",
      SourceFile: "",
      LineNumber: 0,
      ColumnNumber: 0,
      Disposition: "enforce",
    });
    expect(() => {
      context.Flush();
    }).not.toThrow();
    expect(context.InternalErrors).toBe(1);
  });

  it("después de Dispose no acepta eventos", () => {
    const dispatched: unknown[] = [];
    const context = new GuardContext(ResolveConfig(), window, (event) => dispatched.push(event));
    context.Dispose();
    context.Emit("network.request", "Test", {
      Transport: "fetch",
      Url: "x",
      Origin: null,
      HasQuery: false,
      QueryLength: 0,
    });
    context.Flush();
    expect(dispatched).toHaveLength(0);
    expect(context.IsActive()).toBe(false);
    expect(context.IsOwnFunction(42)).toBe(false);
  });
});

describe("MonitorRegistry", () => {
  function FakeMonitor(name: string, failOn?: "start" | "stop"): Monitor {
    let running = false;
    return {
      Name: name,
      Start: () => {
        if (failOn === "start") {
          throw new Error("start failed");
        }
        running = true;
      },
      Stop: () => {
        if (failOn === "stop") {
          throw new Error("stop failed");
        }
        running = false;
      },
      IsRunning: () => running,
    };
  }

  it("aísla fallos de un monitor", () => {
    const onError = vi.fn();
    const registry = new MonitorRegistry(onError);
    registry.Register(FakeMonitor("Broken", "start"));
    registry.Register(FakeMonitor("Healthy"));
    registry.StartAll();
    expect(registry.GetStatus()).toEqual([
      { Name: "Broken", Running: false },
      { Name: "Healthy", Running: true },
    ]);
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it("detiene en orden inverso y continúa ante errores", () => {
    const order: string[] = [];
    const onError = vi.fn();
    const registry = new MonitorRegistry(onError);
    for (const name of ["A", "B", "C"]) {
      const monitor = FakeMonitor(name, name === "B" ? "stop" : undefined);
      const stop = monitor.Stop;
      monitor.Stop = () => {
        order.push(name);
        stop();
      };
      registry.Register(monitor);
    }
    registry.StartAll();
    registry.StopAll();
    expect(order).toEqual(["C", "B", "A"]);
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it("no permite nombres duplicados y expone Get/Count", () => {
    const registry = new MonitorRegistry(vi.fn());
    registry.Register(FakeMonitor("A"));
    expect(() => {
      registry.Register(FakeMonitor("A"));
    }).toThrow();
    expect(registry.Get("A")?.Name).toBe("A");
    expect(registry.Count).toBe(1);
  });

  it("StartAll no reinicia monitores en ejecución", () => {
    const registry = new MonitorRegistry(vi.fn());
    const monitor = FakeMonitor("A");
    const start = vi.spyOn(monitor, "Start");
    registry.Register(monitor);
    registry.StartAll();
    registry.StartAll();
    expect(start).toHaveBeenCalledTimes(1);
  });
});
