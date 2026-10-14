import type { RiskSignal } from "../Core/RiskSignals";
import type { ResolvedConfig } from "../Types/BrowserGuardConfig";
import type { Detector, FindingCandidate } from "../Types/Detector";
import type { CspViolationData, SecurityEvent } from "../Types/SecurityEvent";
import { MatchesAnyOrigin } from "../Utils/UrlUtils";

/**
 * Directivas relacionadas con ejecución de código. Se compara solo el prefijo porque
 * ViolatedDirective puede incluir el valor de la directiva ("script-src 'self'").
 */
const ScriptDirectivePattern =
  /^(script-src|script-src-elem|script-src-attr|trusted-types|require-trusted-types-for)/;

/**
 * Convierte violaciones CSP (evento "csp.violation", de CspMonitor) en hallazgos.
 *
 * Toda violación es relevante (indica algo que la política no esperaba), pero el
 * riesgo aumenta cuando afecta a la ejecución de scripts o involucra un origen
 * bloqueado, y disminuye en modo report-only (la acción no fue bloqueada,
 * pero tampoco indica necesariamente un ataque).
 *
 * Referencia con pesos por defecto:
 * - violación genérica → low;
 * - violación de una directiva de scripts → medium;
 * - recurso de un origen en BlockedOrigins → high o critical.
 *
 * No deduplica ni usa allowlists: la propia política CSP del sitio es la que define
 * qué es esperable, así que cada violación se reporta.
 */
export class CspViolationDetector implements Detector {
  public readonly Name = "CspViolationDetector";
  public readonly Handles = ["csp.violation"] as const;

  public constructor(private readonly Config: ResolvedConfig) {}

  public Analyze(event: SecurityEvent): FindingCandidate {
    const data = event.Data as CspViolationData;
    // EffectiveDirective es la directiva concreta aplicada (p. ej. script-src-elem); algunos
    // navegadores antiguos solo informan ViolatedDirective.
    const directive = data.EffectiveDirective || data.ViolatedDirective;
    const signals: RiskSignal[] = ["csp.violation"];

    if (ScriptDirectivePattern.test(directive)) {
      signals.push("csp.script-directive");
    }
    if (data.Disposition === "report") {
      signals.push("csp.report-only");
    }
    if (
      data.BlockedOrigin !== null &&
      MatchesAnyOrigin(data.BlockedOrigin, this.Config.Network.BlockedOrigins)
    ) {
      signals.push("csp.blocked-origin");
    }

    const action = data.Disposition === "report" ? "reported (report-only)" : "blocked";
    return {
      Category: "csp",
      Title: `CSP violation: ${directive || "unknown directive"}`,
      Description: `The browser ${action} "${data.BlockedUri || "unknown"}" because it violates the "${directive}" directive.`,
      Signals: signals,
      Evidence: { ...data },
    };
  }
}
