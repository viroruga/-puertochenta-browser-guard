import { expect, test } from "@playwright/test";
import type { RemotePayload } from "../src/Index";
import { Findings, OnlyNetwork, OpenFixture, StartGuard } from "./Helpers";

test("envío remoto: el endpoint recibe el hallazgo y el envío no se auto-detecta", async ({
  page,
  request,
}, testInfo) => {
  // Identificador único: los proyectos (chromium, firefox) comparten el servidor.
  const run = `${testInfo.project.name}-${String(Date.now())}`;
  await OpenFixture(page);
  await StartGuard(
    page,
    { Console: "silent", Monitors: OnlyNetwork },
    { RemoteReporting: { Endpoint: "/collect", BatchSize: 1, Metadata: { Run: run } } },
  );
  await page.evaluate(() => window.App.submitPayment("http://unknown.invalid/x"));

  const received = async (): Promise<RemotePayload[]> => {
    const payloads = (await (await request.get("/collected")).json()) as RemotePayload[];
    return payloads.filter((payload) => payload.Metadata?.Run === run);
  };
  await expect.poll(async () => (await received()).length).toBe(1);

  const [payload] = await received();
  expect(payload?.Schema).toBe("browser-guard.findings/v1");
  expect(payload?.Page.Path).toBe("/fixtures/index.html");
  expect(payload?.Findings[0]?.Title).toBe("Unknown outbound request");
  // El POST a /collect usa el fetch original: no genera hallazgos propios.
  expect(await Findings(page)).toHaveLength(1);
  const status = await page.evaluate(() => window.Guard.GetStatus());
  expect(status.Remote).toMatchObject({ Sent: 1 });
  expect(status.Plugins).toEqual([{ Name: "RemoteReporting", Active: true }]);
});

test("modo notice: la consola solo muestra el aviso, nunca los hallazgos", async ({ page }) => {
  const messages: string[] = [];
  page.on("console", (message) => messages.push(message.text()));
  await OpenFixture(page);
  await StartGuard(page, { Preset: "strict", Monitors: OnlyNetwork });
  await page.evaluate(() => window.App.submitPayment("http://unknown.invalid/x"));
  await expect.poll(async () => (await Findings(page)).length).toBe(1);

  expect(messages.filter((text) => text.includes("Security monitoring active"))).toHaveLength(1);
  expect(messages.some((text) => text.includes("BrowserGuard MEDIUM"))).toBe(false);
});
