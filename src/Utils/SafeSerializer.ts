/**
 * Serializador defensivo para evidencia de hallazgos.
 *
 * Objetivos:
 * - nunca lanzar excepciones (getters hostiles, ciclos, proxies);
 * - limitar profundidad, cantidad de claves y longitud de strings (rendimiento);
 * - censurar información sensible (contraseñas, tokens, cookies, JWT, tarjetas).
 *
 * Lo usa RiskEngine para la evidencia de cada hallazgo: todo lo que llega a consola o al
 * endpoint remoto pasa antes por aquí. La censura es por heurística (nombre de clave y
 * patrones de valor); ante la duda se prefiere censurar de más.
 */

/** Límites del serializador. */
export interface SerializerOptions {
  /** Niveles de anidamiento; más allá se reemplaza por "[object]" o "[array]". */
  MaxDepth: number;
  /** Claves por objeto o elementos por arreglo; el resto se omite. */
  MaxKeys: number;
  /** Longitud máxima de cada string (luego de censurar); se agrega "…" al truncar. */
  MaxStringLength: number;
}

const DefaultOptions: SerializerOptions = { MaxDepth: 4, MaxKeys: 30, MaxStringLength: 300 };

/** Texto que reemplaza a un valor censurado. */
export const RedactedValue = "[redacted]";

/**
 * Claves cuyo valor nunca se registra. Es amplia a propósito (p. ej. "token" coincide en
 * cualquier posición): un falso positivo solo oculta un dato de diagnóstico, mientras que
 * un falso negativo filtraría un secreto. Las siglas cortas (cvv, pin, ...) van ancladas
 * para no coincidir dentro de otras palabras.
 */
const SensitiveKeyPattern =
  /pass(word|wd|phrase)?|secret|token|authorization|^auth$|cookie|session|jwt|bearer|credential|api[-_]?key|private[-_]?key|card[-_]?(number|num|no)?$|^(cvv|cvc|pan|ssn|pin)$/i;

/** JWT: tres segmentos base64url separados por puntos; el encabezado empieza con "eyJ". */
const JwtPattern = /eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}/g;

/**
 * Secuencias de 13 a 19 dígitos (con espacios o guiones) compatibles con tarjetas. No
 * valida Luhn: también censura otros números largos, lo que se acepta por privacidad.
 */
const CardPattern = /\b(?:\d[ -]?){12,18}\d\b/g;

/** Token "Bearer xxx". */
const BearerPattern = /bearer\s+[\w.~+/-]+=*/gi;

/**
 * Indica si una clave se considera sensible.
 */
export function IsSensitiveKey(key: string): boolean {
  return SensitiveKeyPattern.test(key);
}

/**
 * Censura patrones sensibles dentro de un string y lo trunca. Se censura antes de truncar
 * para que el corte no deje a la vista un fragmento de un secreto que ya no coincida.
 */
export function SanitizeString(value: string, maxLength = DefaultOptions.MaxStringLength): string {
  const redacted = value
    .replace(JwtPattern, RedactedValue)
    .replace(BearerPattern, `Bearer ${RedactedValue}`)
    .replace(CardPattern, RedactedValue);
  return redacted.length > maxLength ? `${redacted.slice(0, maxLength)}…` : redacted;
}

/** Serializa recursivamente; `seen` corta ciclos. Puede lanzar: SafeSerialize lo contiene. */
function SerializeValue(
  value: unknown,
  depth: number,
  seen: WeakSet<object>,
  options: SerializerOptions,
): unknown {
  switch (typeof value) {
    case "string":
      return SanitizeString(value, options.MaxStringLength);
    case "number":
    case "boolean":
      return value;
    case "undefined":
      return undefined;
    case "bigint":
      return value.toString();
    case "symbol":
      return value.toString();
    case "function":
      return `[function ${value.name || "anonymous"}]`;
  }

  if (value === null) {
    return null;
  }

  const objectValue = value as object;
  // `seen` no se limpia al salir de una rama: un objeto repetido (no cíclico) también se
  // marca "[circular]". Aceptable: evita duplicar evidencia y acota el tamaño.
  if (seen.has(objectValue)) {
    return "[circular]";
  }
  if (depth >= options.MaxDepth) {
    return Array.isArray(objectValue) ? "[array]" : "[object]";
  }
  seen.add(objectValue);

  if (Array.isArray(objectValue)) {
    const items = objectValue.slice(0, options.MaxKeys) as unknown[];
    return items.map((item) => SerializeValue(item, depth + 1, seen, options));
  }

  const result: Record<string, unknown> = {};
  let keys: string[];
  // Solo propiedades propias enumerables: nunca recorre el prototipo. Un Proxy puede
  // lanzar en ownKeys o en cada lectura, de ahí los try/catch.
  try {
    keys = Object.keys(objectValue);
  } catch {
    return "[unserializable]";
  }
  for (const key of keys.slice(0, options.MaxKeys)) {
    if (IsSensitiveKey(key)) {
      result[key] = RedactedValue;
      continue;
    }
    try {
      result[key] = SerializeValue(
        (objectValue as Record<string, unknown>)[key],
        depth + 1,
        seen,
        options,
      );
    } catch {
      result[key] = "[unreadable]";
    }
  }
  return result;
}

/**
 * Produce una copia segura y acotada de un valor arbitrario, apta para JSON. Nunca lanza.
 * Funciones, símbolos y bigint se convierten a texto descriptivo.
 */
export function SafeSerialize(value: unknown, options: Partial<SerializerOptions> = {}): unknown {
  try {
    return SerializeValue(value, 0, new WeakSet(), { ...DefaultOptions, ...options });
  } catch {
    return "[unserializable]";
  }
}
