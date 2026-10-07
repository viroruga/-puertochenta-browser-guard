import { expect, test } from "@playwright/test";
import { CrossOrigin, Findings, FindingTitles, OpenFixture, StartGuard } from "./Helpers";

/** Red, sinks y realms; el resto apagado para aislar los hallazgos. */
const Config = {
  Console: "silent",
  Monitors: { Dom: false, Csp: false, Prototype: false, Runtime: false, Channels: false },
} as const;

test.beforeEach(async ({ page }) => {
  await OpenFixture(page);
  await StartGuard(page, Config);
});

test("evasión con el fetch de un iframe vacío: detectada y reportada", async ({ page }) => {
  await page.evaluate(
    (origin) => window.App.fetchThroughFrame(`${origin}/api/echo?c=x`),
    CrossOrigin,
  );

  await expect
    .poll(() => FindingTitles(page))
    .toEqual(["Same-origin frame realm accessed", "Unknown outbound request"]);
  const [realm, request] = await Findings(page);
  expect(realm?.Evidence).toEqual({ Frame: "about:blank", Access: "contentWindow" });
  expect(request?.Stack).toContain("fetchThroughFrame");
});

test("también por contentDocument.defaultView", async ({ page }) => {
  await page.evaluate(
    (origin) => window.App.fetchThroughFrameDocument(`${origin}/api/echo`),
    CrossOrigin,
  );
  await expect.poll(() => FindingTitles(page)).toContain("Unknown outbound request");
  const [realm] = await Findings(page);
  expect(realm?.Evidence).toMatchObject({ Access: "contentDocument" });
});

test("window.frames[i] después de insertar el iframe también está protegido", async ({ page }) => {
  await page.evaluate(() => {
    window.App.insertBlankFrame();
  });
  await page.waitForTimeout(100);
  await page.evaluate(
    (origin) => window.App.fetchThroughFramesIndex(`${origin}/api/echo`),
    CrossOrigin,
  );
  await expect.poll(() => FindingTitles(page)).toEqual(["Unknown outbound request"]);
});

test("iframes de otro origen se ignoran (postMessage es legítimo)", async ({ page }) => {
  await page.evaluate(
    (origin) => window.App.talkToCrossOriginFrame(`${origin}/fixtures/index.html`),
    CrossOrigin,
  );
  await page.waitForTimeout(300);
  expect(await FindingTitles(page)).toEqual([]);
});

test("URLs javascript: asignadas como propiedad", async ({ page }) => {
  await page.evaluate(() => {
    window.App.setDangerousUrls();
  });
  await expect
    .poll(async () =>
      (await Findings(page)).map((finding) => (finding.Evidence as { Sink: string }).Sink),
    )
    .toEqual(["href", "formAction", "src"]);
  const [href] = await Findings(page);
  expect(href?.Severity).toBe("critical");
  expect(href?.Stack).toContain("setDangerousUrls");
});
