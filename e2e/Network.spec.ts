import { expect, test } from "@playwright/test";
import {
  CrossOrigin,
  Findings,
  FindingTitles,
  OnlyNetwork,
  OpenFixture,
  StartGuard,
} from "./Helpers";

test.beforeEach(async ({ page }) => {
  await OpenFixture(page);
});

test("una página limpia no produce falsos positivos con todos los monitores", async ({ page }) => {
  await StartGuard(page, {
    Preset: "development",
    Console: "silent",
    Integrity: { IntervalMs: 500 },
  });
  const status = await page.evaluate(() => window.Guard.GetStatus());
  expect(status.Monitors.every((monitor) => monitor.Running)).toBe(true);

  await page.waitForTimeout(1500);
  expect(await Findings(page)).toEqual([]);
});

test("fetch sigue funcionando y conserva su identidad pública", async ({ page }) => {
  await StartGuard(page, { Console: "silent", Monitors: OnlyNetwork });
  const result = await page.evaluate(async () => {
    const response = await fetch("/api/echo");
    return {
      Status: response.status,
      Body: (await response.json()) as unknown,
      Patched: window.fetch !== window.Originals.fetch,
      Name: window.fetch.name,
      Source: window.fetch.toString(),
    };
  });
  expect(result).toMatchObject({
    Status: 200,
    Body: { Verdict: null },
    Patched: true,
    Name: "fetch",
  });
  expect(result.Source).toContain("[native code]");
  expect(await Findings(page)).toEqual([]);
});

test("solicitud a origen desconocido: medium, URL saneada y stack limpio", async ({ page }) => {
  await StartGuard(page, { Console: "silent", Monitors: OnlyNetwork });
  await page.evaluate(() =>
    window.App.submitPayment("http://unknown.invalid/collect?token=secret"),
  );

  await expect.poll(() => FindingTitles(page)).toEqual(["Unknown outbound request"]);
  const [finding] = await Findings(page);
  expect(finding?.Severity).toBe("medium");
  expect(finding?.Evidence).toMatchObject({ Url: "http://unknown.invalid/collect", Method: "GET" });
  expect(finding?.Stack).toContain("submitPayment");
  expect(finding?.Stack).toContain("app.js");
  expect(finding?.Stack).not.toContain("index.js");
  expect(JSON.stringify(finding)).not.toContain("secret");
});

test("XHR y WebSocket se observan y conservan su comportamiento", async ({ page }) => {
  await StartGuard(page, { Console: "silent", Monitors: OnlyNetwork });
  const result = await page.evaluate((crossOrigin) => {
    const request = window.App.sendLegacyRequest(`${crossOrigin}/api/echo`);
    const socket = window.App.openSocket(crossOrigin.replace("http", "ws") + "/socket");
    return {
      XhrState: request.readyState,
      IsWebSocket: socket instanceof WebSocket,
      OpenConstant: WebSocket.OPEN,
    };
  }, CrossOrigin);
  expect(result).toEqual({ XhrState: 1, IsWebSocket: true, OpenConstant: 1 });

  await expect
    .poll(async () => (await Findings(page)).map((finding) => finding.Evidence))
    .toEqual([
      expect.objectContaining({ Transport: "xhr", Method: "POST" }),
      expect.objectContaining({ Transport: "websocket" }),
    ]);
});

test("Stop restaura exactamente las funciones originales", async ({ page }) => {
  await StartGuard(page, { Console: "silent" });
  const restored = await page.evaluate(() => {
    window.Guard.Stop();
    return {
      Fetch: window.fetch === window.Originals.fetch,
      Open: XMLHttpRequest.prototype.open === window.Originals.open,
      Send: XMLHttpRequest.prototype.send === window.Originals.send,
      WebSocket: window.WebSocket === window.Originals.WebSocket,
      Running: window.Guard.IsRunning(),
    };
  });
  expect(restored).toEqual({
    Fetch: true,
    Open: true,
    Send: true,
    WebSocket: true,
    Running: false,
  });
});
