import { expect, test, type Page } from "@playwright/test";
import type { SecurityFinding } from "../src/Index";
import { CrossOrigin, OpenFixture, StartGuard } from "./Helpers";

/** Solo los canales de salida, para aislar sus hallazgos. */
const ChannelsOnly = {
  Console: "silent",
  Monitors: {
    Fetch: false,
    Xhr: false,
    WebSocket: false,
    Dom: false,
    Csp: false,
    Prototype: false,
    Runtime: false,
    Sinks: false,
  },
} as const;

async function NetworkFindings(page: Page): Promise<SecurityFinding[]> {
  return page.evaluate(() =>
    window.Guard.GetReport().Findings.filter((finding) => finding.Category === "network"),
  );
}

async function FindingTitled(page: Page, title: string): Promise<SecurityFinding | undefined> {
  return (await NetworkFindings(page)).find((finding) => finding.Title === title);
}

test.beforeEach(async ({ page }) => {
  await OpenFixture(page);
  await StartGuard(page, ChannelsOnly);
});

test("exfiltración con new Image().src y query larga → medium (sin registrar la query)", async ({
  page,
}) => {
  const secret = "s".repeat(120);
  await page.evaluate(
    ([origin, value]) => {
      window.App.leakWithImage(`${origin}/fixtures/pixel.gif?c=${value}`);
    },
    [CrossOrigin, secret] as const,
  );

  await expect
    .poll(async () => (await FindingTitled(page, "Resource loaded from unknown origin"))?.Severity)
    .toBe("medium");
  const finding = await FindingTitled(page, "Resource loaded from unknown origin");
  expect(finding?.Evidence).toMatchObject({ InitiatorType: "img", QueryLength: 122 });
  expect(JSON.stringify(finding)).not.toContain(secret);
});

test("sendBeacon a un origen desconocido, con stack de la aplicación", async ({ page }) => {
  const accepted = await page.evaluate(
    (origin) => window.App.leakWithBeacon(`${origin}/collect`),
    CrossOrigin,
  );
  expect(accepted).toBe(true);

  await expect
    .poll(async () => (await FindingTitled(page, "Beacon sent to unknown origin"))?.Severity)
    .toBe("medium");
  const finding = await FindingTitled(page, "Beacon sent to unknown origin");
  expect(finding?.Stack).toContain("leakWithBeacon");
});

test("formulario enviado a un origen desconocido, sin leer sus campos", async ({ page }) => {
  await page.evaluate((origin) => {
    window.App.submitFormTo(`${origin}/api/echo`);
  }, CrossOrigin);

  await expect
    .poll(async () => (await FindingTitled(page, "Form submitted to unknown origin"))?.Severity)
    .toBe("medium");
  const finding = await FindingTitled(page, "Form submitted to unknown origin");
  expect(finding?.Evidence).toMatchObject({ Method: "POST", Url: `${CrossOrigin}/api/echo` });
  expect(JSON.stringify(finding)).not.toContain("hunter2");
});

test("window.open y EventSource hacia orígenes desconocidos", async ({ page }) => {
  await page.evaluate((origin) => {
    window.App.openWindowTo(`${origin}/fixtures/index.html`);
    window.App.openStream(`${origin}/api/echo`);
  }, CrossOrigin);

  await expect
    .poll(async () => (await NetworkFindings(page)).map((finding) => finding.Title).sort())
    .toEqual(["Event stream from unknown origin", "Window opened to unknown origin"]);
});

test("registro de un service worker → low", async ({ page }) => {
  await page.evaluate(() => window.App.registerWorker());
  await expect
    .poll(async () => (await FindingTitled(page, "Service worker registered"))?.Severity)
    .toBe("low");
  await page.evaluate(async () => {
    for (const registration of await navigator.serviceWorker.getRegistrations()) {
      await registration.unregister();
    }
  });
});

test("recursos y envíos al propio origen no generan hallazgos; Stop restaura", async ({ page }) => {
  await page.evaluate(() => {
    window.App.leakWithImage("/fixtures/pixel.gif?c=1");
    window.App.leakWithBeacon("/collect");
  });
  await page.waitForTimeout(500);
  expect(await NetworkFindings(page)).toEqual([]);

  const restored = await page.evaluate(() => {
    const read = (): unknown =>
      Object.getOwnPropertyDescriptor(Navigator.prototype, "sendBeacon")?.value;
    const patched = read();
    window.Guard.Stop();
    return read() !== patched;
  });
  expect(restored).toBe(true);
});
