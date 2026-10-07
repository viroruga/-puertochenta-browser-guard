import { defineConfig, devices } from "@playwright/test";

const Port = Number(process.env.E2E_PORT ?? 4173);
const IsCi = process.env.CI !== undefined;

/**
 * Tests end-to-end en navegadores reales contra el bundle compilado (dist/).
 * Requieren `pnpm build` previo: el script `test:e2e` lo ejecuta.
 * Las rutas son relativas a este archivo (e2e/).
 */
export default defineConfig({
  testDir: ".",
  outputDir: "../test-results",
  fullyParallel: true,
  forbidOnly: IsCi,
  retries: IsCi ? 1 : 0,
  reporter: IsCi
    ? [["github"], ["html", { open: "never", outputFolder: "../playwright-report" }]]
    : "list",
  use: {
    baseURL: `http://localhost:${Port}`,
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: {
    command: "node Server.mjs",
    url: `http://localhost:${Port}/fixtures/index.html`,
    reuseExistingServer: !IsCi,
    env: { E2E_PORT: String(Port) },
  },
});
