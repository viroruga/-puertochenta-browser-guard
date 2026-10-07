import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["tests/**/*.test.ts"],
    restoreMocks: true,
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      reporter: ["text", "html"],
      thresholds: {
        "src/Core/**": { lines: 80, functions: 80, branches: 80, statements: 80 },
        "src/Detectors/**": { lines: 80, functions: 80, branches: 80, statements: 80 },
      },
    },
  },
});
