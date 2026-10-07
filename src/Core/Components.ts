import { CspViolationDetector } from "../Detectors/CspViolationDetector";
import { NetworkDetector } from "../Detectors/NetworkDetector";
import { PrototypePollutionDetector } from "../Detectors/PrototypePollutionDetector";
import { RuntimeIntegrityDetector } from "../Detectors/RuntimeIntegrityDetector";
import { ScriptInjectionDetector } from "../Detectors/ScriptInjectionDetector";
import { CspMonitor } from "../Monitors/CspMonitor";
import { DomMonitor } from "../Monitors/DomMonitor";
import { FetchMonitor } from "../Monitors/FetchMonitor";
import { PrototypeMonitor } from "../Monitors/PrototypeMonitor";
import { RuntimeMonitor } from "../Monitors/RuntimeMonitor";
import { WebSocketMonitor } from "../Monitors/WebSocketMonitor";
import { XhrMonitor } from "../Monitors/XhrMonitor";
import { ConsoleReporter } from "../Reporters/ConsoleReporter";
import type { Reporter } from "../Reporters/Reporter";
import type { ResolvedConfig } from "../Types/BrowserGuardConfig";
import type { Detector } from "../Types/Detector";
import type { Monitor } from "../Types/Monitor";
import type { GuardContext } from "./GuardContext";

/**
 * Información de la página que necesitan los detectores.
 * GuardContext la implementa; en tests puede sustituirse por un objeto simple.
 */
export interface PageInfo {
  GetPageOrigin(): string;
  GetPageProtocol(): string;
}

/**
 * Fábricas de monitores, en orden de inicio.
 *
 * RuntimeMonitor va primero: su baseline debe capturar las funciones originales
 * antes de que los monitores de red instalen sus interceptores. Al detener,
 * MonitorRegistry recorre la lista en orden inverso.
 */
const MonitorFactories: readonly (readonly [
  keyof ResolvedConfig["Monitors"],
  (context: GuardContext) => Monitor,
])[] = [
  ["Runtime", (context) => new RuntimeMonitor(context)],
  ["Fetch", (context) => new FetchMonitor(context)],
  ["Xhr", (context) => new XhrMonitor(context)],
  ["WebSocket", (context) => new WebSocketMonitor(context)],
  ["Dom", (context) => new DomMonitor(context)],
  ["Csp", (context) => new CspMonitor(context)],
  ["Prototype", (context) => new PrototypeMonitor(context)],
];

/**
 * Crea los monitores habilitados en la configuración.
 */
export function CreateMonitors(context: GuardContext): Monitor[] {
  return MonitorFactories.filter(([toggle]) => context.Config.Monitors[toggle]).map(([, create]) =>
    create(context),
  );
}

/**
 * Crea los detectores. Son livianos y solo actúan cuando reciben eventos,
 * por lo que se crean todos y quedan inactivos si su monitor está deshabilitado.
 */
export function CreateDetectors(config: ResolvedConfig, page: PageInfo): Detector[] {
  return [
    new NetworkDetector(config, page),
    new ScriptInjectionDetector(config, page),
    new CspViolationDetector(config),
    new PrototypePollutionDetector(),
    new RuntimeIntegrityDetector(),
  ];
}

/**
 * Crea los reporters del núcleo. Los plugins pueden agregar otros (p. ej. RemoteReporting).
 * En los modos de consola "notice" y "silent" los hallazgos no se imprimen.
 */
export function CreateReporters(config: ResolvedConfig): Reporter[] {
  return config.Console === "findings" ? [new ConsoleReporter(config.ConsoleMinSeverity)] : [];
}
