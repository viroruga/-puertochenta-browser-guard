/**
 * Verificación de tipos del paquete publicado, tal como lo ve un consumidor:
 * se importa por nombre (resolución vía "exports" contra dist/), no por ruta relativa.
 * Se compila con `pnpm test:package` después de `pnpm build`.
 */
import { BrowserGuard, type GuardPlugin, type SecurityFinding } from "@puertochenta/browser-guard";
import { AntiScraping, type BotAssessment } from "@puertochenta/browser-guard/anti-scraping";
import { RemoteReporting, type RemotePayload } from "@puertochenta/browser-guard/remote";

// Los plugins de los subpaths son compatibles con el núcleo.
const plugins: GuardPlugin[] = [
  AntiScraping({ ProtectAt: "bot" }),
  RemoteReporting({ Endpoint: "https://security.example.com/findings" }),
];

const guard = BrowserGuard.Start({ Preset: "strict", Plugins: plugins });

guard.On("Bot", (assessment: BotAssessment) => assessment.Verdict);
guard.On("Critical", (finding: SecurityFinding) => finding.RiskScore);

export const payload: RemotePayload | null = null;
export const status = guard.GetStatus().Plugins;

// La API anterior a los plugins ya no existe.
// @ts-expect-error -- AntiScraping ahora es un plugin.
BrowserGuard.Start({ AntiScraping: {} });
