// Genera los fixtures que requieren compilación (después de `pnpm build`).
import { build } from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const Fixtures = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

// Build de producción típico: un único archivo minificado con la librería y la app.
// keepNames conserva los nombres de función para poder verificar el stack trace.
await build({
  entryPoints: [join(Fixtures, "BundledApp.js")],
  outfile: join(Fixtures, "generated", "bundled.js"),
  bundle: true,
  format: "esm",
  minify: true,
  keepNames: true,
  target: "es2020",
  logLevel: "warning",
});
