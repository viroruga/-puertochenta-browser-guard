import type { RiskSignal } from "../Core/RiskSignals";
import type { Detector, FindingCandidate } from "../Types/Detector";
import type { SecurityEvent, SinkData, SinkName } from "../Types/SecurityEvent";

const IndicatorSignals: Readonly<Record<string, RiskSignal>> = {
  "script-tag": "xss.script-tag",
  "auto-event-handler": "xss.auto-event-handler",
  "event-handler": "xss.event-handler",
  "javascript-url": "xss.javascript-url",
  "embedded-content": "xss.embedded-content",
  "sensitive-access": "xss.sensitive-access",
  probe: "xss.probe",
  "url-reflected": "xss.url-reflected",
  "string-code": "xss.string-code",
};

const IndicatorDescriptions: Readonly<Record<string, string>> = {
  "script-tag": "a <script> element",
  "auto-event-handler": "an event handler that runs without user interaction (onerror, onload...)",
  "event-handler": "an inline event handler",
  "javascript-url": "a javascript: URL",
  "embedded-content": "embedded content (iframe, object, embed, base or srcdoc)",
  "sensitive-access": "access to sensitive data or obfuscation (cookies, storage, eval, atob...)",
  probe: "a typical proof-of-concept call (alert, prompt, confirm)",
  "url-reflected": "a suspicious value taken from the page URL",
  "string-code": "code passed as a string",
};

/** Sinks obsoletos o desaconsejados en sí mismos. */
const LegacySinks: ReadonlySet<SinkName> = new Set(["document.write"]);

/**
 * Evalúa escrituras en sinks de DOM XSS.
 *
 * No toda escritura es un ataque: un handler inline (onclick) es "low"; un handler que
 * se ejecuta solo (onerror) junto a una prueba como alert() es "high"; si además el
 * contenido proviene de la URL de la página (XSS reflejado en el DOM), es "critical".
 */
export class XssSinkDetector implements Detector {
  public readonly Name = "XssSinkDetector";
  public readonly Handles = ["dom.sink"] as const;

  public Analyze(event: SecurityEvent): FindingCandidate | null {
    const data = event.Data as SinkData;
    const signals = data.Indicators.map((indicator) => IndicatorSignals[indicator]).filter(
      (signal): signal is RiskSignal => signal !== undefined,
    );
    if (signals.length === 0) {
      return null;
    }
    if (LegacySinks.has(data.Sink)) {
      signals.push("xss.legacy-sink");
    }

    const isCode = data.Sink === "setTimeout" || data.Sink === "setInterval";
    const details = data.Indicators.map((indicator) => IndicatorDescriptions[indicator])
      .filter((text): text is string => text !== undefined)
      .join("; ");
    const target = data.Target ? ` on <${data.Target}>` : "";

    return {
      Category: "xss",
      Title: isCode
        ? `Code string passed to ${data.Sink}`
        : `Dangerous content written to ${data.Sink}`,
      Description: `Content written to ${data.Sink}${target} contains ${details}.`,
      Signals: signals,
      Evidence: {
        Sink: data.Sink,
        Target: data.Target,
        Length: data.Length,
        Indicators: data.Indicators,
      },
    };
  }
}
