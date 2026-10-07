import { describe, expect, it, vi } from "vitest";
import { EventBus } from "../src/Core/EventBus";

interface TestEvents extends Record<string, unknown> {
  Ping: number;
  Pong: string;
}

describe("EventBus", () => {
  it("emite a los manejadores suscritos con el payload tipado", () => {
    const bus = new EventBus<TestEvents>();
    const handler = vi.fn();
    bus.On("Ping", handler);
    bus.Emit("Ping", 42);
    expect(handler).toHaveBeenCalledWith(42);
  });

  it("no notifica eventos distintos", () => {
    const bus = new EventBus<TestEvents>();
    const handler = vi.fn();
    bus.On("Ping", handler);
    bus.Emit("Pong", "x");
    expect(handler).not.toHaveBeenCalled();
  });

  it("Off y la función retornada por On desuscriben", () => {
    const bus = new EventBus<TestEvents>();
    const first = vi.fn();
    const second = vi.fn();
    const unsubscribe = bus.On("Ping", first);
    bus.On("Ping", second);
    unsubscribe();
    bus.Off("Ping", second);
    bus.Emit("Ping", 1);
    expect(first).not.toHaveBeenCalled();
    expect(second).not.toHaveBeenCalled();
    expect(bus.ListenerCount()).toBe(0);
  });

  it("Off sobre un evento sin manejadores no falla", () => {
    const bus = new EventBus<TestEvents>();
    expect(() => {
      bus.Off("Ping", vi.fn());
    }).not.toThrow();
  });

  it("Once se ejecuta una única vez", () => {
    const bus = new EventBus<TestEvents>();
    const handler = vi.fn();
    bus.Once("Ping", handler);
    bus.Emit("Ping", 1);
    bus.Emit("Ping", 2);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith(1);
    expect(bus.ListenerCount("Ping")).toBe(0);
  });

  it("Once puede cancelarse con Off usando el manejador original", () => {
    const bus = new EventBus<TestEvents>();
    const handler = vi.fn();
    bus.Once("Ping", handler);
    bus.Off("Ping", handler);
    bus.Emit("Ping", 1);
    expect(handler).not.toHaveBeenCalled();
  });

  it("Once puede cancelarse con la función retornada", () => {
    const bus = new EventBus<TestEvents>();
    const handler = vi.fn();
    const cancel = bus.Once("Ping", handler);
    cancel();
    bus.Emit("Ping", 1);
    expect(handler).not.toHaveBeenCalled();
  });

  it("aísla errores de manejadores y los notifica a OnError", () => {
    const onError = vi.fn();
    const bus = new EventBus<TestEvents>(onError);
    const after = vi.fn();
    bus.On("Ping", () => {
      throw new Error("boom");
    });
    bus.On("Ping", after);
    expect(() => {
      bus.Emit("Ping", 1);
    }).not.toThrow();
    expect(after).toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith(expect.any(Error), "Ping");
  });

  it("permite desuscribirse durante una emisión sin saltar manejadores", () => {
    const bus = new EventBus<TestEvents>();
    const calls: string[] = [];
    const first = (): void => {
      calls.push("first");
      bus.Off("Ping", first);
    };
    bus.On("Ping", first);
    bus.On("Ping", () => calls.push("second"));
    bus.Emit("Ping", 1);
    bus.Emit("Ping", 2);
    expect(calls).toEqual(["first", "second", "second"]);
  });

  it("Clear elimina todos los manejadores", () => {
    const bus = new EventBus<TestEvents>();
    bus.On("Ping", vi.fn());
    bus.Once("Pong", vi.fn());
    bus.Clear();
    expect(bus.ListenerCount()).toBe(0);
  });
});
