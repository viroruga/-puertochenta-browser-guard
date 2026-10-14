import type { PageInfo } from "../Core/Components";
import type { RiskSignal } from "../Core/RiskSignals";
import type { ResolvedConfig } from "../Types/BrowserGuardConfig";
import type { Detector, FindingCandidate } from "../Types/Detector";
import type { DomElementData, SecurityEvent } from "../Types/SecurityEvent";
import { ClassifyOrigin, type OriginClassification } from "../Utils/UrlUtils";

/** Esquemas que ejecutan código arbitrario sin pasar por un origen de red. */
const DangerousSchemes: ReadonlySet<string> = new Set(["javascript:", "data:"]);

/**
 * Esquemas con contenido generado en tiempo de ejecución (equivalente a inline): un
 * script blob: lo construyó código de la propia página, no un servidor identificable.
 */
const GeneratedSchemes: ReadonlySet<string> = new Set(["blob:"]);

/**
 * Analiza elementos insertados en el DOM (evento "dom.element-inserted", de DomMonitor):
 * script, iframe, object, embed.
 *
 * No asume que todo script dinámico sea un ataque: combina señales (creación
 * dinámica, inline, origen desconocido, ausencia de integrity, esquema peligroso,
 * origen bloqueado) y deja que RiskEngine calcule la severidad. Los pesos son
 * configurables mediante Risk.Weights.
 *
 * Referencia con pesos por defecto:
 * - script externo conocido → info
 * - script externo desconocido → medium
 * - desconocido + sin integrity → high
 * - origen bloqueado → critical
 *
 * Para evitar falsos positivos, lo que viene en el HTML original (ParserInserted) no
 * suma "creación dinámica" y sus scripts inline se ignoran; los orígenes permitidos
 * (AllowedScriptOrigins, servicios declarados) quedan en info y no superan el umbral
 * por defecto.
 */
export class ScriptInjectionDetector implements Detector {
  public readonly Name = "ScriptInjectionDetector";
  public readonly Handles = ["dom.element-inserted"] as const;

  public constructor(
    private readonly Config: ResolvedConfig,
    private readonly Page: PageInfo,
  ) {}

  public Analyze(event: SecurityEvent): FindingCandidate | null {
    const data = event.Data as DomElementData;
    return data.TagName === "script" ? this.AnalyzeScript(data) : this.AnalyzeEmbedded(data);
  }

  /** Clasifica el origen del elemento contra la lista permitida indicada y BlockedOrigins. */
  private Classify(data: DomElementData, allowed: readonly string[]): OriginClassification {
    return ClassifyOrigin(
      data.Origin,
      this.Page.GetPageOrigin(),
      allowed,
      this.Config.Network.BlockedOrigins,
    );
  }

  /**
   * Scripts: el orden de las ramas importa. Inline/blob: primero (no hay origen que
   * clasificar), luego los esquemas peligrosos y por último el origen de red.
   */
  private AnalyzeScript(data: DomElementData): FindingCandidate | null {
    const signals: RiskSignal[] = data.ParserInserted ? [] : ["script.dynamic"];
    const scheme = data.Scheme ?? "";
    let title: string;
    let classification: OriginClassification | "inline" = "inline";

    if (data.Inline || GeneratedSchemes.has(scheme)) {
      // Los scripts inline del HTML original son contenido normal de la página.
      if (data.ParserInserted) {
        return null;
      }
      signals.push("script.inline");
      title = "Inline script inserted dynamically";
    } else if (DangerousSchemes.has(scheme)) {
      signals.push("script.dangerous-scheme");
      title = `Script with ${scheme} URL inserted`;
    } else {
      // Para scripts solo vale AllowedScriptOrigins: permitir que un origen reciba
      // solicitudes (Network.AllowedOrigins) no implica confiarle la ejecución de código.
      classification = this.Classify(data, this.Config.Dom.AllowedScriptOrigins);
      switch (classification) {
        case "blocked":
          signals.push("script.external", "script.blocked-origin");
          title = "Script loaded from blocked origin";
          break;
        case "unknown":
          signals.push("script.external", "script.unknown-origin");
          if (!data.Integrity) {
            signals.push("script.missing-integrity");
            title = "Unknown external script without integrity";
          } else {
            title = "Unknown external script";
          }
          break;
        case "allowed":
          signals.push("script.external");
          title = "Known external script inserted";
          break;
        case "non-network":
          // Por ejemplo, scripts inyectados por extensiones del navegador.
          signals.push("script.external");
          title = "Script from non-network source inserted";
          break;
        default:
          // same-origin: sin señales propias; solo hay hallazgo si fue dinámico (info).
          title = "Same-origin script inserted dynamically";
      }
    }

    if (signals.length === 0) {
      return null;
    }

    return {
      Category: "script-injection",
      Title: title,
      Description: this.Describe("script", data, classification),
      Signals: signals,
      Evidence: {
        TagName: data.TagName,
        Src: data.Src,
        Origin: data.Origin,
        Classification: classification,
        Inline: data.Inline,
        // Del código inline solo se registra el largo, nunca el contenido.
        InlineLength: data.InlineLength,
        // El hash de integrity no aporta al análisis; basta saber si está.
        Integrity: data.Integrity ? "present" : "missing",
        CrossOrigin: data.CrossOrigin,
        Type: data.Type,
        Async: data.Async,
        Defer: data.Defer,
        ParserInserted: data.ParserInserted,
      },
    };
  }

  /**
   * iframe, object y embed. object/embed suman riesgo propio porque cargan contenido de
   * plugins, raro en sitios modernos. Un iframe puede apuntar tanto a servicios de red
   * como a scripts de terceros (widgets), por eso se aceptan ambas listas permitidas.
   */
  private AnalyzeEmbedded(data: DomElementData): FindingCandidate | null {
    const signals: RiskSignal[] = data.ParserInserted ? [] : ["dom.embedded-content"];
    if (data.TagName === "object" || data.TagName === "embed") {
      signals.push("dom.plugin-content");
    }

    let classification: OriginClassification | "inline" = "inline";
    const scheme = data.Scheme ?? "";
    if (DangerousSchemes.has(scheme)) {
      signals.push("script.dangerous-scheme");
    } else if (!data.Inline) {
      classification = this.Classify(data, [
        ...this.Config.Network.AllowedOrigins,
        ...this.Config.Dom.AllowedScriptOrigins,
      ]);
      if (classification === "blocked") {
        signals.push("dom.blocked-origin");
      } else if (classification === "unknown") {
        signals.push("dom.unknown-origin");
      }
    }

    if (signals.length === 0) {
      return null;
    }

    return {
      Category: "dom",
      Title: `<${data.TagName}> element inserted`,
      Description: this.Describe(data.TagName, data, classification),
      Signals: signals,
      Evidence: {
        TagName: data.TagName,
        Src: data.Src,
        Origin: data.Origin,
        Classification: classification,
        Inline: data.Inline,
        ParserInserted: data.ParserInserted,
      },
    };
  }

  /** Descripción legible: qué elemento, hacia qué origen y cómo se insertó. */
  private Describe(
    tagName: string,
    data: DomElementData,
    classification: OriginClassification | "inline",
  ): string {
    const how = data.ParserInserted ? "during page parsing" : "dynamically";
    if (classification === "inline") {
      return `An inline <${tagName}> element was inserted ${how}.`;
    }
    return `A <${tagName}> element pointing to ${data.Origin ?? data.Src ?? "an unknown source"} (${classification}) was inserted ${how}.`;
  }
}
