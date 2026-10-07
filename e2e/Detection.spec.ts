import { expect, test } from "@playwright/test";
import { CrossOrigin, Findings, FindingTitles, OpenFixture, StartGuard } from "./Helpers";

const Silent = { Console: "silent" } as const;

test("violación CSP real del navegador", async ({ page }) => {
  await OpenFixture(page, "/fixtures/csp.html");
  await StartGuard(page, {
    ...Silent,
    Monitors: {
      Fetch: false,
      Xhr: false,
      WebSocket: false,
      Dom: false,
      Prototype: false,
      Runtime: false,
    },
  });
  await page.evaluate((origin) => {
    window.App.loadExternalImage(`${origin}/fixtures/pixel.png?id=1`);
  }, CrossOrigin);

  await expect.poll(() => FindingTitles(page)).toEqual(["CSP violation: img-src"]);
  const [finding] = await Findings(page);
  expect(finding?.Category).toBe("csp");
  expect(finding?.Evidence).toMatchObject({
    BlockedUri: `${CrossOrigin}/fixtures/pixel.png`,
    Disposition: "enforce",
  });
});

test("script dinámico de origen desconocido sin integrity → high", async ({ page }) => {
  await OpenFixture(page);
  await StartGuard(page, { ...Silent, Monitors: { Runtime: false, Prototype: false } });
  await page.evaluate(() => {
    window.App.injectScript("http://unknown.invalid/library.js");
  });

  await expect
    .poll(() => FindingTitles(page))
    .toContain("Unknown external script without integrity");
  const finding = (await Findings(page)).find((item) => item.Category === "script-injection");
  expect(finding?.Severity).toBe("high");
});

test("prototype pollution en Object.prototype → critical", async ({ page }) => {
  await OpenFixture(page);
  await StartGuard(page, { ...Silent, Integrity: { IntervalMs: 500 } });
  await page.evaluate(() => {
    (Object.prototype as Record<string, unknown>).polluted = true;
  });

  await expect.poll(() => FindingTitles(page)).toContain("Object.prototype.polluted added");
  const finding = (await Findings(page)).find((item) => item.Category === "prototype-pollution");
  expect(finding?.Severity).toBe("critical");

  // Revertir no genera un hallazgo nuevo.
  await page.evaluate(() => {
    delete (Object.prototype as Record<string, unknown>).polluted;
  });
  await page.waitForTimeout(1500);
  expect(await FindingTitles(page)).toEqual(["Object.prototype.polluted added"]);
});

test("reemplazo de una función nativa del runtime → high", async ({ page }) => {
  await OpenFixture(page);
  await StartGuard(page, { ...Silent, Integrity: { IntervalMs: 500 } });
  await page.evaluate(() => {
    const original = window.setTimeout.bind(window);
    window.setTimeout = function setTimeout(...args: Parameters<typeof original>) {
      return original(...args);
    } as typeof window.setTimeout;
  });

  await expect.poll(() => FindingTitles(page)).toContain("setTimeout modified");
  const finding = (await Findings(page)).find((item) => item.Category === "runtime-integrity");
  expect(finding?.Severity).toBe("high");
});
