import { expect, test, type Page } from "@playwright/test";
import type { SecurityFinding } from "../src/Index";
import { OpenFixture, StartGuard } from "./Helpers";

/** Solo el monitor de sinks, para aislar los hallazgos de DOM XSS. */
const SinksOnly = {
  Console: "silent",
  Monitors: {
    Fetch: false,
    Xhr: false,
    WebSocket: false,
    Dom: false,
    Csp: false,
    Prototype: false,
    Runtime: false,
  },
} as const;

async function XssFindings(page: Page): Promise<SecurityFinding[]> {
  return page.evaluate(() =>
    window.Guard.GetReport().Findings.filter((finding) => finding.Category === "xss"),
  );
}

test("payload clásico en innerHTML → high, con stack de la aplicación", async ({ page }) => {
  await OpenFixture(page);
  await StartGuard(page, SinksOnly);
  const rendered = await page.evaluate(
    () =>
      window.App.renderComment('<img src="x" onerror="window.Executed = true; alert(1)">')
        .innerHTML,
  );
  // El comportamiento de innerHTML no cambia (el payload se ejecuta igual: solo se detecta).
  expect(rendered).toBe('<img src="x" onerror="window.Executed = true; alert(1)">');

  await expect.poll(async () => (await XssFindings(page)).length).toBe(1);
  const [finding] = await XssFindings(page);
  expect(finding).toMatchObject({
    Severity: "high",
    Title: "Dangerous content written to innerHTML",
  });
  expect(finding?.Stack).toContain("renderComment");
  expect(finding?.Stack).toContain("app.js");
  expect(JSON.stringify(finding)).not.toContain("onerror=");
});

test("XSS reflejado: valor de la URL escrito en innerHTML → critical", async ({ page }) => {
  const payload = '<img src=x onerror="alert(document.domain)">';
  await OpenFixture(page, `/fixtures/index.html?q=${encodeURIComponent(payload)}`);
  await StartGuard(page, SinksOnly);
  await page.evaluate(() => {
    window.App.renderSearchFromUrl();
  });

  await expect.poll(async () => (await XssFindings(page))[0]?.Severity).toBe("critical");
  const [finding] = await XssFindings(page);
  expect(finding?.Signals).toContain("xss.url-reflected");
  expect(finding?.Stack).toContain("renderSearchFromUrl");
});

test("código como string en setTimeout → high", async ({ page }) => {
  await OpenFixture(page);
  await StartGuard(page, SinksOnly);
  await page.evaluate(() => {
    window.App.runLater("window.Leaked = document.cookie");
  });

  await expect
    .poll(async () => (await XssFindings(page)).map((f) => f.Title))
    .toEqual(["Code string passed to setTimeout"]);
  const [finding] = await XssFindings(page);
  expect(finding?.Severity).toBe("high");
  expect(finding?.Stack).toContain("runLater");
  // setTimeout sigue ejecutando el código (solo se observa).
  await expect.poll(() => page.evaluate(() => "Leaked" in window)).toBe(true);
});

test("HTML inofensivo no genera hallazgos y Stop restaura los sinks", async ({ page }) => {
  await OpenFixture(page);
  await StartGuard(page, SinksOnly);
  await page.evaluate(() => {
    window.App.renderComment("<ul><li>uno</li><li><b>dos</b></li></ul>");
    window.App.renderComment('<a href="javascript:void(0)" onclick="return false">x</a>');
  });
  await page.waitForTimeout(300);
  const titles = (await XssFindings(page)).map((finding) => finding.Severity);
  // Solo el handler inline con interacción: "low", nunca más.
  expect(titles).toEqual(["low"]);

  const restored = await page.evaluate(() => {
    window.Guard.Stop();
    return {
      InnerHTML:
        Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML")?.set ===
        window.Originals.innerHTMLSetter,
      SetTimeout: window.setTimeout === window.Originals.setTimeout,
    };
  });
  expect(restored).toEqual({ InnerHTML: true, SetTimeout: true });
});
