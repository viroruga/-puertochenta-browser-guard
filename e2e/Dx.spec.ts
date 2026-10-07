import { expect, test, type Page } from "@playwright/test";
import { CrossOrigin, Findings, OnlyNetwork, OpenFixture, StartGuard } from "./Helpers";

test.beforeEach(async ({ page }) => {
  await OpenFixture(page);
});

test("modo aprendizaje: la configuración aprendida elimina el hallazgo", async ({ page }) => {
  await StartGuard(page, {
    Console: "silent",
    Monitors: OnlyNetwork,
    Learning: { Enabled: true },
  });
  const learned = await page.evaluate(async (origin) => {
    await fetch(`${origin}/api/echo?token=secret`).catch(() => undefined);
    await fetch("/api/echo");
    await new Promise((resolve) => setTimeout(resolve, 50));
    return window.Guard.GetLearnedConfig();
  }, CrossOrigin);
  expect(learned).toEqual({
    Network: { AllowedOrigins: [CrossOrigin] },
    Dom: { AllowedScriptOrigins: [] },
  });

  // Con la configuración aprendida, el mismo tráfico ya no produce hallazgos.
  await page.evaluate(() => {
    window.Guard.Stop();
  });
  await StartGuard(page, { Console: "silent", Monitors: OnlyNetwork, ...learned });
  await page.evaluate(async (origin) => {
    await fetch(`${origin}/api/echo`).catch(() => undefined);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }, CrossOrigin);
  expect(await Findings(page)).toEqual([]);
});

/** Simula el wrapper de Sentry: envuelve el fetch actual y marca el original. */
async function WrapFetchLikeSentry(page: Page): Promise<void> {
  await page.evaluate(() => {
    // eslint-disable-next-line @typescript-eslint/unbound-method -- Como Sentry: la marca debe apuntar a la referencia original.
    const original = window.fetch;
    const wrapper = function fetch(...args: Parameters<typeof original>) {
      return original.apply(window, args);
    };
    Object.defineProperty(wrapper, "__sentry_original__", { value: original });
    window.fetch = wrapper;
  });
}

for (const declared of [true, false]) {
  test(`wrapper de Sentry sobre fetch (servicio ${declared ? "declarado" : "no declarado"})`, async ({
    page,
  }) => {
    await StartGuard(page, {
      Console: "silent",
      Monitors: { Dom: false, Csp: false, Prototype: false, Sinks: false },
      Integrity: { IntervalMs: 500 },
      Services: declared ? ["sentry"] : [],
    });
    await WrapFetchLikeSentry(page);
    // El tráfico que pasa por el wrapper sigue siendo observado.
    await page.evaluate(async (origin) => {
      await fetch(`${origin}/api/echo`).catch(() => undefined);
    }, CrossOrigin);
    await page.waitForTimeout(1200);

    const categories = (await Findings(page)).map((finding) => finding.Category);
    expect(categories).toContain("network");
    if (declared) {
      expect(categories).not.toContain("runtime-integrity");
    } else {
      expect(categories).toContain("runtime-integrity");
    }
  });
}

test("store: Subscribe notifica y GetSnapshot refleja el último hallazgo", async ({ page }) => {
  await StartGuard(page, { Console: "silent", Monitors: OnlyNetwork });
  const result = await page.evaluate(async (origin) => {
    let notifications = 0;
    const { GetSnapshot, Subscribe } = window.Guard;
    const before = GetSnapshot();
    const unsubscribe = Subscribe(() => notifications++);
    await fetch(`${origin}/api/echo`).catch(() => undefined);
    await new Promise((resolve) => setTimeout(resolve, 50));
    unsubscribe();
    const after = GetSnapshot();
    return {
      Notified: notifications > 0,
      Changed: before !== after,
      Stable: after === GetSnapshot(),
      Category: after.LastFinding?.Category,
      Total: after.Statistics.Total,
    };
  }, CrossOrigin);
  expect(result).toEqual({
    Notified: true,
    Changed: true,
    Stable: true,
    Category: "network",
    Total: 1,
  });
});
