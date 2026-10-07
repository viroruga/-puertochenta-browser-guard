// @vitest-environment node
import { describe, expect, it } from "vitest";

/**
 * Simula un entorno SSR (Next.js, Nuxt): sin window ni document.
 */
describe("SSR", () => {
  it("el import no falla y Start retorna una instancia inerte", async () => {
    expect(typeof window).toBe("undefined");
    const { BrowserGuard } = await import("../src/Index");

    const guard = BrowserGuard.Start({ Preset: "strict" });
    expect(guard.IsRunning()).toBe(false);
    expect(guard.GetStatus()).toMatchObject({ Supported: false, Running: false, Monitors: [] });
    expect(guard.GetReport().Findings).toEqual([]);
    expect(() => {
      guard.On("Threat", () => undefined);
      guard.Stop();
      BrowserGuard.Stop();
    }).not.toThrow();
    expect(BrowserGuard.GetInstance()).toBeNull();
  });
});
