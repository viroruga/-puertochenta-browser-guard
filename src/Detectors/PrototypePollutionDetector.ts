import type { RiskSignal } from "../Core/RiskSignals";
import type { Detector, FindingCandidate } from "../Types/Detector";
import type {
  PrototypeChangeData,
  PrototypeChangeKind,
  SecurityEvent,
} from "../Types/SecurityEvent";

/**
 * Propiedades típicas de payloads de prototype pollution o de escalamiento
 * de privilegios mediante propiedades heredadas. Comparación sin distinguir mayúsculas.
 *
 * Por qué importan: si `isAdmin` aparece en Object.prototype, todo objeto sin esa
 * propiedad propia (`user.isAdmin`) pasa a heredarla, y un chequeo de permisos en el
 * cliente puede darse por satisfecho.
 */
export const SuspiciousKeys: ReadonlySet<string> = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "isadmin",
  "admin",
  "role",
  "roles",
  "permissions",
  "polluted",
  "isauthenticated",
  "authorized",
]);

/** Señal base según el tipo de cambio. */
const ChangeSignals: Record<PrototypeChangeKind, RiskSignal> = {
  added: "prototype.added",
  removed: "prototype.removed",
  modified: "prototype.modified",
};

/** Verbo usado en la descripción ("added to Object.prototype"). */
const ChangeVerbs: Record<PrototypeChangeKind, string> = {
  added: "added to",
  removed: "removed from",
  modified: "modified on",
};

/**
 * Analiza cambios en prototipos nativos (evento "prototype.changed", de PrototypeMonitor,
 * que compara periódicamente los descriptores de Object/Array/Function/String/Promise).
 *
 * No todo cambio es crítico: un polyfill que agrega un método a Array.prototype
 * es "low". El riesgo aumenta cuando:
 * - la propiedad es típica de pollution (isAdmin, role, polluted, ...);
 * - el prototipo afectado es Object.prototype (lo heredan casi todos los objetos);
 * - una función nativa es reemplazada o eliminada.
 *
 * No deduplica: el monitor solo emite lo que cambió desde la verificación anterior
 * (omite reversiones al estado inicial y limita los eventos por verificación), así que
 * cada evento ya es un cambio nuevo.
 */
export class PrototypePollutionDetector implements Detector {
  public readonly Name = "PrototypePollutionDetector";
  public readonly Handles = ["prototype.changed"] as const;

  public Analyze(event: SecurityEvent): FindingCandidate {
    const data = event.Data as PrototypeChangeData;
    const signals: RiskSignal[] = [ChangeSignals[data.Change]];

    if (SuspiciousKeys.has(data.Property.toLowerCase())) {
      signals.push("prototype.suspicious-key");
    }
    if (data.Target === "Object.prototype") {
      signals.push("prototype.object-root");
    }
    // Solo si antes era nativa: reemplazar el método de un polyfill no es lo mismo que
    // sustituir una implementación del navegador. LooksNative ausente significa que la
    // propiedad se eliminó o dejó de ser una función.
    if (data.PreviousLooksNative === true && data.LooksNative !== true) {
      signals.push("prototype.native-overridden");
    }

    const isNativeOverride = signals.includes("prototype.native-overridden");
    const description =
      `Property "${data.Property}" was ${ChangeVerbs[data.Change]} ${data.Target}.` +
      (isNativeOverride ? " A native implementation was replaced or removed." : "") +
      (signals.includes("prototype.suspicious-key")
        ? " The property name is commonly used in prototype pollution payloads."
        : "");

    return {
      Category: "prototype-pollution",
      Title: `${data.Target}.${data.Property} ${data.Change}`,
      Description: description,
      Signals: signals,
      Evidence: { ...data },
    };
  }
}
