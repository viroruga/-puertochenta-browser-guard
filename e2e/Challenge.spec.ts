import { expect, test } from "@playwright/test";
import { OnlyNetwork, OpenFixture, StartGuard } from "./Helpers";

interface Verification {
  Decision: "allow" | "challenge" | "deny";
  Proof: { Status: string };
  Verdict: { Verdict: string } | null;
}

test("la prueba de trabajo se resuelve en el navegador y el servidor la valida", async ({
  page,
}, testInfo) => {
  await OpenFixture(page);
  const started = Date.now();
  await StartGuard(
    page,
    { Console: "silent", Monitors: OnlyNetwork },
    { AntiScraping: { Challenge: { Endpoint: "/api/challenge" } } },
  );
  await expect
    .poll(() => page.evaluate(() => window.Guard.GetBotAssessment()?.Proof), { timeout: 20_000 })
    .toBe("ready");
  testInfo.annotations.push({
    type: "proof-of-work",
    description: `${testInfo.project.name}: ${String(Date.now() - started)} ms (difficulty 14)`,
  });

  const result = await page.evaluate(async () => {
    const response = await fetch("/api/protected");
    return { Status: response.status, Body: (await response.json()) as unknown };
  });
  // La prueba es válida; el navegador de Playwright es automatizado (webdriver), así que
  // el veredicto declarado es "bot" y la decisión recomendada es deny.
  expect(result.Body).toMatchObject({
    Proof: { Status: "valid" },
    Verdict: { Verdict: "bot" },
    Decision: "deny",
  });
});

test("clientes sin JavaScript y headers falsificados son rechazados", async ({ request }) => {
  const curl = (await (await request.get("/api/protected")).json()) as Verification;
  expect(curl).toMatchObject({ Decision: "deny", Proof: { Status: "missing" } });

  const forged = (await (
    await request.get("/api/protected", {
      headers: { "X-BrowserGuard-Verdict": "human; score=0; sid=x; proof=abc.def~1" },
    })
  ).json()) as Verification;
  expect(forged).toMatchObject({ Decision: "deny", Proof: { Status: "invalid-signature" } });
});
