// Verifica el paquete tal como lo recibe un usuario (después de `pnpm build`):
// 1. empaqueta el .tgz que se publicaría en npm;
// 2. lo instala en un proyecto consumidor temporal;
// 3. compila Consumer.ts con tres modos de resolución de módulos;
// 4. importa cada entrada desde Node (simula SSR).

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const Here = dirname(fileURLToPath(import.meta.url));
const Root = join(Here, "..", "..");
const Tsc = join(Root, "node_modules", "typescript", "bin", "tsc");
const Shell = process.platform === "win32";

const Workspace = mkdtempSync(join(tmpdir(), "browser-guard-package-"));

function Run(command, args, cwd) {
  execFileSync(command, args, { cwd, stdio: "inherit", shell: Shell });
}

try {
  // 1. Empaquetar.
  Run("pnpm", ["pack", "--pack-destination", Workspace], Root);
  const tarball = readdirSync(Workspace).find((file) => file.endsWith(".tgz"));
  if (!tarball) {
    throw new Error("pnpm pack did not produce a tarball");
  }

  // 2. Instalar en un consumidor (el paquete no tiene dependencias: no requiere red).
  const consumer = join(Workspace, "consumer");
  mkdirSync(consumer);
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({ name: "consumer", private: true, type: "module" }),
  );
  Run(
    "npm",
    ["install", join(Workspace, tarball), "--no-audit", "--no-fund", "--silent"],
    consumer,
  );
  copyFileSync(join(Here, "Consumer.ts"), join(consumer, "Consumer.ts"));

  // 3. Compilar con cada modo de resolución.
  const modes = [
    { module: "ESNext", moduleResolution: "Bundler" },
    { module: "NodeNext", moduleResolution: "NodeNext" },
    // Resolución clásica, sin soporte de "exports": la cubre "typesVersions".
    { module: "ESNext", moduleResolution: "Node10", ignoreDeprecations: "6.0" },
  ];
  for (const mode of modes) {
    writeFileSync(
      join(consumer, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: {
          ...mode,
          target: "ES2022",
          lib: ["ES2022", "DOM"],
          strict: true,
          noEmit: true,
          types: [],
        },
        include: ["Consumer.ts"],
      }),
    );
    console.log(`\n▶ tsc (moduleResolution: ${mode.moduleResolution})`);
    Run("node", [Tsc, "-p", consumer], consumer);
  }

  // 4. Importar cada entrada en Node, como en SSR.
  const entries = [
    "@puertochenta/browser-guard",
    "@puertochenta/browser-guard/anti-scraping",
    "@puertochenta/browser-guard/remote",
    "@puertochenta/browser-guard/server",
  ];
  const script = entries
    .map((entry) => `const m${entries.indexOf(entry)} = await import("${entry}");`)
    .join("\n");
  writeFileSync(
    join(consumer, "ssr.mjs"),
    `${script}\nconst guard = m0.BrowserGuard.Start({ Plugins: [m1.AntiScraping(), m2.RemoteReporting({ Endpoint: "https://x.example" })] });\nif (guard.IsRunning()) throw new Error("must be inert in SSR");\nconsole.log("SSR import OK:", Object.keys(m0), Object.keys(m1), Object.keys(m2));\n` +
      // Backend en Node: un header sin prueba se rechaza y se pueden emitir desafíos.
      `const secret = "x".repeat(32);\n` +
      `const result = await m3.VerifyRequest({ "x-browserguard-verdict": "human; score=0" }, { Secret: secret });\n` +
      `if (result.Decision !== "deny") throw new Error("forged header must be denied");\n` +
      `const issued = await m3.CreateChallenge({ Secret: secret, Difficulty: 8 });\n` +
      `console.log("Server entry OK:", result.Proof.Status, issued.Difficulty);\n`,
  );
  console.log("\n▶ node ssr.mjs");
  Run("node", ["ssr.mjs"], consumer);
  console.log("\n✔ Package check passed");
} finally {
  rmSync(Workspace, { recursive: true, force: true });
}
