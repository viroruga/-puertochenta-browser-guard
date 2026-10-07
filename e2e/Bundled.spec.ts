import { expect, test } from "@playwright/test";
import type { SecurityFinding } from "../src/Index";

declare global {
  interface Window {
    BundledApp: { submitBundledPayment(url: string): Promise<unknown> };
  }
}

/**
 * En producción la librería y la aplicación suelen compartir un mismo archivo
 * (bundle minificado). El stack debe seguir apuntando al código de la aplicación.
 */
test("stack trace útil cuando la librería está empaquetada junto con la app", async ({
  page,
  browserName,
}) => {
  await page.goto("/fixtures/bundled.html");
  await page.waitForFunction(() => typeof window.BrowserGuard === "function");
  await page.evaluate(() => {
    window.Guard = window.BrowserGuard.Start({ Console: "silent", Monitors: { Runtime: false } });
  });
  await page.evaluate(() => window.BundledApp.submitBundledPayment("http://unknown.invalid/x"));

  const findings = async (): Promise<SecurityFinding[]> =>
    page.evaluate(() => window.Guard.GetReport().Findings);
  await expect.poll(async () => (await findings()).length).toBe(1);
  const [finding] = await findings();
  // El primer frame es la función de la aplicación, en el mismo archivo que la librería.
  const firstFrame = finding?.Stack?.split("\n")[0] ?? "";
  expect(firstFrame).toContain("bundled.js");
  if (browserName === "chromium") {
    // V8 usa la propiedad `name` (conservada por keepNames); Firefox muestra el
    // identificador minificado: recuperar el nombre original es tarea de los source maps.
    expect(firstFrame).toContain("submitBundledPayment");
  }
});
