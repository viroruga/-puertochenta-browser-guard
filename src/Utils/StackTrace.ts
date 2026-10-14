/**
 * Captura y limpieza de stack traces.
 *
 * El stack debe apuntar al código de la aplicación que originó la acción, no a
 * BrowserGuard. Los frames internos se descartan POR POSICIÓN: el Error se crea dentro
 * de la trampa del Proxy, que es invocada directamente por quien llamó a la función
 * interceptada; basta con descartar ese primer frame. No se puede usar el nombre de
 * archivo: en producción la librería suele compartir el bundle con la aplicación.
 *
 * Lo usa Core/FunctionPatch: los hooks con `CaptureStack` reciben el stack del llamador.
 *
 * Rendimiento: crear un Error y leer `.stack` cuesta microsegundos, pero no es gratis.
 * Solo se captura en los puntos de interceptación que lo usan (fetch, XHR.send,
 * new WebSocket, canales de salida y sinks de DOM XSS), nunca en callbacks masivos como
 * MutationObserver.
 */

/**
 * Patrones de archivos de la librería cuando se sirve como archivo propio (p. ej. el
 * servidor de desarrollo de Vite). Es un filtro adicional, no el mecanismo principal.
 * Acepta separadores "/" y "\" (Windows) y el nombre del paquete con "/" reemplazado
 * por "_", como lo nombra el pre-bundle de dependencias de Vite.
 */
const InternalPathPatterns: readonly RegExp[] = [
  /[\\/]browser-guard[\\/](src|dist)[\\/]/i,
  /@puertochenta[\\/_]browser-guard/i,
];

/** Frames del motor sin ubicación útil. */
const NoisePattern = /^(<anonymous>|native|\[native code\])$/;

/**
 * Frame V8: "at fn (url:line:col)" o "at url:line:col". Grupos: 1 = función (opcional,
 * sin el prefijo "async"), 2 = archivo, 3 = línea, 4 = columna. El archivo es no codicioso
 * para que los ":" de la URL ("https://...") no se confundan con línea y columna.
 */
const V8Frame = /^\s*at\s+(?:(?:async\s+)?(.+?)\s+\()?(.+?):(\d+):(\d+)\)?\s*$/;

/** Frame SpiderMonkey / JavaScriptCore: "fn@url:line:col" (función vacía si es anónima). */
const GeckoFrame = /^\s*(.*?)@(.+?):(\d+):(\d+)\s*$/;

/** Frame de un stack trace ya interpretado. */
export interface StackFrame {
  /** Nombre de la función, o null si es anónima o código de nivel superior. */
  FunctionName: string | null;
  /** URL o ruta del archivo, tal como la informa el motor. */
  File: string;
  /** Línea, base 1. */
  Line: number;
  /** Columna, base 1. */
  Column: number;
}

/**
 * Convierte un stack en texto a una lista de frames estructurados. Las líneas que no son
 * frames (p. ej. el "Error: mensaje" inicial de V8) y los frames sin ubicación se omiten.
 */
export function ParseStack(stack: string): StackFrame[] {
  const frames: StackFrame[] = [];
  for (const line of stack.split("\n")) {
    const match = V8Frame.exec(line) ?? GeckoFrame.exec(line);
    if (!match) {
      continue;
    }
    const file = match[2] ?? "";
    if (NoisePattern.test(file)) {
      continue;
    }
    frames.push({
      FunctionName: match[1] ? match[1] : null,
      File: file,
      Line: Number(match[3]),
      Column: Number(match[4]),
    });
  }
  return frames;
}

/**
 * Indica si un frame pertenece a un archivo propio de BrowserGuard.
 */
export function IsInternalFrame(frame: StackFrame): boolean {
  return InternalPathPatterns.some((pattern) => pattern.test(frame.File));
}

/**
 * Reduce una ruta o URL a su nombre de archivo, sin query string.
 */
function ShortFileName(file: string): string {
  const withoutQuery = file.split(/[?#]/)[0] ?? file;
  const segments = withoutQuery.split(/[\\/]/);
  return segments[segments.length - 1] ?? withoutQuery;
}

/**
 * Formatea un frame de forma compacta: "submitPayment() Payment.ts:82:5".
 */
export function FormatFrame(frame: StackFrame): string {
  const location = `${ShortFileName(frame.File)}:${frame.Line}:${frame.Column}`;
  return frame.FunctionName ? `${frame.FunctionName}() ${location}` : location;
}

/**
 * Limpia un stack existente: descarta los primeros `skipFrames` frames y los de
 * archivos propios, y limita la cantidad. Retorna undefined si no queda ningún frame.
 *
 * El salto posicional se aplica ANTES del filtro por archivo: así funciona aunque la
 * librería esté dentro del mismo bundle que la aplicación.
 */
export function CleanStack(stack: string, maxFrames: number, skipFrames = 0): string | undefined {
  const frames = ParseStack(stack)
    .slice(skipFrames)
    .filter((frame) => !IsInternalFrame(frame))
    .slice(0, maxFrames)
    .map(FormatFrame);
  return frames.length > 0 ? frames.join("\n") : undefined;
}

/** `Error.stackTraceLimit` no está en los tipos estándar: es una extensión de V8. */
type ErrorWithLimit = ErrorConstructor & { stackTraceLimit?: number };

/**
 * Eleva Error.stackTraceLimit (solo existe en V8) para que el frame interno no consuma
 * el límite por defecto. Retorna el valor anterior para restaurarlo.
 */
export function RaiseStackTraceLimit(frames: number): number | undefined {
  const errorConstructor = Error as ErrorWithLimit;
  const previous = errorConstructor.stackTraceLimit;
  if (typeof previous === "number" && previous < frames) {
    errorConstructor.stackTraceLimit = frames;
  }
  return previous;
}

/**
 * Restaura el valor retornado por RaiseStackTraceLimit. Si era undefined (motor sin
 * stackTraceLimit) no hace nada.
 */
export function RestoreStackTraceLimit(previous: number | undefined): void {
  if (typeof previous === "number") {
    (Error as ErrorWithLimit).stackTraceLimit = previous;
  }
}

/**
 * Stack de quien llamó a la función donde se creó `error`: descarta el primer frame
 * (esa función) y los de archivos propios. Nunca lanza.
 */
export function CallerStackFrom(error: Error, maxFrames: number): string | undefined {
  try {
    return error.stack ? CleanStack(error.stack, maxFrames, 1) : undefined;
  } catch {
    return undefined;
  }
}
