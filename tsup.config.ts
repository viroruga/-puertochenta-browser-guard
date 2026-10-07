import { defineConfig } from "tsup";

export default defineConfig({
  // Núcleo y plugins opcionales como entradas separadas: quien no importe un plugin
  // no lo incluye en su bundle.
  entry: {
    index: "src/Index.ts",
    "anti-scraping": "src/Plugins/AntiScrapingPlugin.ts",
    remote: "src/Plugins/RemoteReportingPlugin.ts",
    // Verificación en el backend (Node, Deno, Bun, edge): sin dependencias del DOM.
    server: "src/Server/Index.ts",
  },
  format: ["esm"],
  target: "es2020",
  platform: "browser",
  // tsup inyecta `baseUrl` al generar tipos; TypeScript 6 lo marca como obsoleto.
  dts: { compilerOptions: { ignoreDeprecations: "6.0" } },
  sourcemap: true,
  clean: true,
  treeshake: true,
  // El código compartido entre entradas va a chunks comunes (sin duplicados).
  splitting: true,
  minify: false,
});
