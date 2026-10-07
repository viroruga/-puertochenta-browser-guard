import { expect, test } from "@playwright/test";
import { CrossOrigin, Findings, OnlyNetwork, OpenFixture, StartGuard } from "./Helpers";

/**
 * Los navegadores controlados por Playwright exponen navigator.webdriver === true:
 * son exactamente el tipo de cliente automatizado que esta protección debe detectar.
 */
test.beforeEach(async ({ page }) => {
  await OpenFixture(page);
  await StartGuard(page, { Console: "silent", Monitors: OnlyNetwork }, { AntiScraping: {} });
});

test("navegador automatizado → veredicto bot", async ({ page }) => {
  await expect
    .poll(() => page.evaluate(() => window.Guard.GetBotAssessment()?.Verdict))
    .toBe("bot");
  const assessment = await page.evaluate(() => window.Guard.GetBotAssessment());
  expect(assessment?.Signals).toContain("bot.webdriver");
  expect(
    (await Findings(page)).some((finding) => finding.Title === "Browser automation detected"),
  ).toBe(true);
});

test("el contenido protegido se retira del DOM y Stop lo repone", async ({ page }) => {
  await expect.poll(() => page.locator("#protected").textContent()).toBe("Content unavailable.");
  expect(await page.content()).not.toContain("$1,249.00");

  await page.evaluate(() => {
    window.Guard.Stop();
  });
  await expect(page.locator("#protected")).toHaveText("Wholesale price: $1,249.00");
});

test("header de veredicto solo en solicitudes al propio origen", async ({ page }) => {
  await expect
    .poll(() => page.evaluate(() => window.Guard.GetBotAssessment()?.Verdict))
    .toBe("bot");
  const verdicts = await page.evaluate(async (crossOrigin) => {
    const read = async (url: string): Promise<unknown> =>
      ((await (await fetch(url)).json()) as { Verdict: unknown }).Verdict;
    return { Same: await read("/api/echo"), Cross: await read(`${crossOrigin}/api/echo`) };
  }, CrossOrigin);

  const sessionId = await page.evaluate(() => window.Guard.GetStatus().SessionId);
  expect(verdicts.Same).toMatch(new RegExp(String.raw`^bot; score=\d+; sid=${sessionId ?? ""}$`));
  expect(verdicts.Cross).toBeNull();
});
