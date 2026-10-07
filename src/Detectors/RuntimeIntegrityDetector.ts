import type { RiskSignal } from "../Core/RiskSignals";
import type { Detector, FindingCandidate } from "../Types/Detector";
import type {
  RuntimeChangePhase,
  RuntimeModificationData,
  SecurityEvent,
} from "../Types/SecurityEvent";

/**
 * Funciones cuyo reemplazo permite ejecutar código arbitrario u ocultar wrappers.
 */
export const CriticalRuntimeTargets: ReadonlySet<string> = new Set([
  "eval",
  "Function",
  "Function.prototype.toString",
]);

const PhaseSignals: Record<RuntimeChangePhase, RiskSignal> = {
  change: "runtime.modified",
  baseline: "runtime.preexisting",
  removed: "runtime.removed",
};

const PhaseDescriptions: Record<RuntimeChangePhase, string> = {
  change: "was replaced after BrowserGuard started",
  baseline: "was already modified when BrowserGuard started",
  removed: "was removed or is no longer a function",
};

/**
 * Evalúa modificaciones de funciones críticas del runtime.
 *
 * Combina la fase del cambio con el análisis de NativeFunctionUtils: un reemplazo
 * por una función que no parece nativa es más grave que uno por una función
 * nativa (p. ej. un bind) o un Proxy. Librerías legítimas de observabilidad también
 * envuelven fetch/XHR; por eso un reemplazo por sí solo es "medium" y no "critical".
 */
export class RuntimeIntegrityDetector implements Detector {
  public readonly Name = "RuntimeIntegrityDetector";
  public readonly Handles = ["runtime.modified"] as const;

  public Analyze(event: SecurityEvent): FindingCandidate {
    const data = event.Data as RuntimeModificationData;
    const signals: RiskSignal[] = [PhaseSignals[data.Phase]];

    if (data.Analysis && !data.Analysis.LooksNative) {
      signals.push("runtime.non-native");
    }
    if (CriticalRuntimeTargets.has(data.Target)) {
      signals.push("runtime.critical-target");
    }

    const nativeNote = data.Analysis
      ? data.Analysis.LooksNative
        ? " The new value still looks native (it may be a Proxy or bound function)."
        : ` The new value does not look native (${data.Analysis.Signals.join(", ")}).`
      : "";

    return {
      Category: "runtime-integrity",
      Title: `${data.Target} ${data.Phase === "removed" ? "removed" : "modified"}`,
      Description: `${data.Target} ${PhaseDescriptions[data.Phase]}.${nativeNote}`,
      Signals: signals,
      Evidence: {
        Target: data.Target,
        Phase: data.Phase,
        LooksNative: data.Analysis?.LooksNative,
        Confidence: data.Analysis?.Confidence,
        AnalysisSignals: data.Analysis?.Signals,
      },
    };
  }
}
