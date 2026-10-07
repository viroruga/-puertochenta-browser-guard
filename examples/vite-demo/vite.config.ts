import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const Source = (path: string): string =>
  fileURLToPath(new URL(`../../src/${path}`, import.meta.url));

// La demo consume el código fuente de la librería directamente para reflejar cambios sin
// compilar el paquete. Los subpaths (plugins) van antes que la raíz: los alias se evalúan
// en orden y "@puertochenta/browser-guard" también es prefijo de ellos.
export default defineConfig({
  resolve: {
    alias: [
      {
        find: "@puertochenta/browser-guard/anti-scraping",
        replacement: Source("Plugins/AntiScrapingPlugin.ts"),
      },
      {
        find: "@puertochenta/browser-guard/remote",
        replacement: Source("Plugins/RemoteReportingPlugin.ts"),
      },
      { find: "@puertochenta/browser-guard", replacement: Source("Index.ts") },
    ],
  },
  server: {
    fs: { allow: ["../.."] },
  },
});
