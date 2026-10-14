import type { RiskSignal } from "../Core/RiskSignals";
import type { Detector, FindingCandidate } from "../Types/Detector";
import type {
  RealmAccessData,
  RuntimeChangePhase,
  RuntimeModificationData,
  SecurityEvent,
} from "../Types/SecurityEvent";

/**
 * Funciones cuyo reemplazo permite ejecutar código arbitrario u ocultar wrappers
 * (un Function.prototype.toString falso hace que cualquier wrapper parezca nativo).
 */
export const CriticalRuntimeTargets: ReadonlySet<string> = new Set([
  "eval",
  "Function",
  "Function.prototype.toString",
]);

/** Señal base según cuándo se observó el cambio. */
const PhaseSignals: Record<RuntimeChangePhase, RiskSignal> = {
  change: "runtime.modified",
  baseline: "runtime.preexisting",
  removed: "runtime.removed",
};

/** Fragmento de la descripción según la fase. */
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
 *
 * Consume:
 * - "runtime.modified" (RuntimeMonitor): funciones críticas reemplazadas después de
 *   iniciar (medium), ya modificadas al iniciar (low) o eliminadas (medium). Sumar
 *   "no parece nativa" y "objetivo crítico" (eval, Function, toString) eleva a
 *   high/critical. Los wrappers de servicios declarados (TrustedWrapperMarkers) los
 *   filtra el monitor antes de emitir;
 * - "runtime.realm" (RealmMonitor): acceso al realm de un iframe del mismo origen (low).
 */
export class RuntimeIntegrityDetector implements Detector {
  public readonly Name = "RuntimeIntegrityDetector";
  public readonly Handles = ["runtime.modified", "runtime.realm"] as const;

  public Analyze(event: SecurityEvent): FindingCandidate {
    return event.Type === "runtime.realm"
      ? this.AnalyzeRealm(event.Data as RealmAccessData)
      : this.AnalyzeModification(event.Data as RuntimeModificationData);
  }

  /**
   * Acceso al realm de un iframe del mismo origen: técnica habitual para obtener APIs sin
   * interceptar. BrowserGuard ya extendió su monitoreo a ese realm; se reporta como low
   * porque algunos componentes legítimos (editores, sandboxes) también lo hacen.
   */
  private AnalyzeRealm(data: RealmAccessData): FindingCandidate {
    return {
      Category: "runtime-integrity",
      Title: "Same-origin frame realm accessed",
      Description: `A script accessed the ${data.Access} of a same-origin iframe (${data.Frame}), a common way to obtain unmonitored copies of fetch and other APIs. BrowserGuard extended its monitoring into that frame.`,
      Signals: ["runtime.realm-access"],
      Evidence: { Frame: data.Frame, Access: data.Access },
    };
  }

  /**
   * Combina la fase con el análisis de la nueva función. Sin Analysis (p. ej. eliminada o
   * reemplazada por algo que no es función) solo cuentan la fase y el objetivo.
   */
  private AnalyzeModification(data: RuntimeModificationData): FindingCandidate {
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
