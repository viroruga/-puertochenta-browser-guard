/**
 * Análisis heurístico de funciones: ¿esta función sigue siendo la nativa del navegador
 * o fue reemplazada por un wrapper? Lo usan RuntimeMonitor y PrototypeMonitor para
 * caracterizar cambios, y RuntimeIntegrityDetector para puntuarlos.
 */
import type { FunctionAnalysis } from "../Types/SecurityEvent";

/**
 * Referencia a Function.prototype.toString capturada al cargar el módulo.
 * Si un atacante reemplaza toString (o Function.prototype.call) después,
 * el análisis sigue usando el original.
 */
// eslint-disable-next-line @typescript-eslint/unbound-method -- Se conserva la referencia para compararla por identidad.
const OriginalToString = Function.prototype.toString;
// call.bind deja la invocación fijada desde ya: un reemplazo posterior de
// Function.prototype.call tampoco afecta a CallNativeToString.
const CallNativeToString = Function.prototype.call.bind(OriginalToString) as (
  fn: unknown,
) => string;

/**
 * Cuerpo de función nativa: "function fetch() { [native code] }". Admite nombre vacío
 * (funciones nativas anónimas, p. ej. resultado de bind) y los espacios y saltos de
 * línea que agrega cada motor.
 */
const NativeBodyPattern = /^function\s*[\w$]*\s*\(\s*\)\s*\{\s*\[native code\]\s*\}\s*$/;

/**
 * Obtiene el código fuente de una función usando el toString capturado. Retorna null si
 * toString lanza (p. ej. un Proxy revocado).
 */
function SafeSource(fn: unknown): string | null {
  try {
    return CallNativeToString(fn);
  } catch {
    return null;
  }
}

/**
 * Indica si Function.prototype.toString fue reemplazado desde la carga del módulo.
 * Un toString alterado es una técnica común para ocultar wrappers.
 */
export function IsToStringTampered(): boolean {
  return Function.prototype.toString !== OriginalToString;
}

/**
 * Analiza si una función parece nativa combinando varias señales:
 *
 * 1. Código fuente con forma "[native code]" (obtenido con el toString original).
 * 2. El `toString` propio de la función no fue sobrescrito (técnica de ocultamiento).
 * 3. Ausencia de `prototype` en funciones no constructoras (los métodos nativos no lo tienen;
 *    las funciones declaradas con `function` sí).
 * 4. Coincidencia del `name` con el nombre esperado.
 *
 * Limitación conocida: un Proxy sobre una función nativa reporta "[native code]".
 * Por eso esta utilidad se combina con la comparación de referencias contra un baseline.
 */
export function AnalyzeFunction(
  fn: unknown,
  options: { ExpectedName?: string; IsConstructor?: boolean } = {},
): FunctionAnalysis {
  const signals: string[] = [];

  if (typeof fn !== "function") {
    return { LooksNative: false, Confidence: 1, Signals: ["not-a-function"] };
  }

  let score = 0;
  const maxScore = 4;

  const source = SafeSource(fn);
  if (source !== null && NativeBodyPattern.test(source)) {
    score++;
  } else {
    signals.push("non-native-source");
  }

  if (!Object.prototype.hasOwnProperty.call(fn, "toString")) {
    score++;
  } else {
    signals.push("own-tostring-override");
  }

  const hasPrototype = Object.prototype.hasOwnProperty.call(fn, "prototype");
  if (options.IsConstructor === true || !hasPrototype) {
    score++;
  } else {
    signals.push("unexpected-prototype");
  }

  if (options.ExpectedName === undefined || fn.name === options.ExpectedName) {
    score++;
  } else {
    signals.push("name-mismatch");
  }

  // No suma ni resta puntaje: es un estado global, no una propiedad de esta función.
  if (IsToStringTampered()) {
    signals.push("tostring-tampered");
  }

  // El código fuente es condición necesaria; de las otras tres señales se tolera que
  // falle una (p. ej. un `name` distinto en algún motor) para evitar falsos positivos.
  const looksNative = !signals.includes("non-native-source") && score >= maxScore - 1;
  // La confianza refleja cuántas señales coinciden con el veredicto.
  const confidence = looksNative ? score / maxScore : (maxScore - score + 1) / (maxScore + 1);

  return {
    LooksNative: looksNative,
    Confidence: Math.round(confidence * 100) / 100,
    Signals: signals,
  };
}
