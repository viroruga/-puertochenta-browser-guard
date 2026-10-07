import { FunctionPatch, type PatchPart } from "../Core/FunctionPatch";
import type { SinkData, SinkName } from "../Types/SecurityEvent";
import {
  AnalyzeAttribute,
  AnalyzeCode,
  AnalyzeMarkup,
  type MarkupIndicator,
  type PageHref,
} from "../Utils/MarkupIndicators";
import { BaseMonitor } from "./BaseMonitor";

type SinkWindow = Window & typeof globalThis;

/** Ventana durante la cual una escritura equivalente no se vuelve a reportar. */
export const SinkDedupeWindowMs = 10_000;

/** Máximo de claves recordadas para deduplicar (memoria acotada). */
const MaxDedupeEntries = 300;

/**
 * Cómo observar un sink: dónde vive, qué parte se intercepta y cómo analizar la llamada.
 * Analyze debe ser barato: se ejecuta en cada llamada y retorna null para ignorarla.
 */
interface SinkSpec {
  Sink: SinkName;
  Owner: (window: SinkWindow) => object | undefined;
  Key: string;
  Part: PatchPart;
  Analyze: (
    thisArg: unknown,
    args: readonly unknown[],
    pageHref: PageHref,
  ) => { Indicators: MarkupIndicator[]; Target: string | null; Length: number } | null;
}

function TagOf(element: unknown): string | null {
  return typeof (element as Element | null)?.tagName === "string"
    ? (element as Element).tagName.toLowerCase()
    : null;
}

/** Analiza el primer argumento string como HTML (setters y métodos de un argumento). */
function MarkupAt(index: number, target: (thisArg: unknown) => string | null): SinkSpec["Analyze"] {
  return (thisArg, args, pageHref) => {
    const value = args[index];
    if (typeof value !== "string") {
      // Valores no string (p. ej. TrustedHTML) ya pasaron por una política o no son HTML.
      return null;
    }
    const indicators = AnalyzeMarkup(value, pageHref);
    return indicators
      ? { Indicators: indicators, Target: target(thisArg), Length: value.length }
      : null;
  };
}

function CodeString(): SinkSpec["Analyze"] {
  return (_thisArg, args, pageHref) => {
    const code = args[0];
    // Solo el código como string es un sink; una función es el uso normal.
    return typeof code === "string" && code.trim() !== ""
      ? { Indicators: AnalyzeCode(code, pageHref), Target: null, Length: code.length }
      : null;
  };
}

const OnElement = (window: SinkWindow): object => window.Element.prototype;

/**
 * Sinks observados. eval y new Function se omiten a propósito: interceptarlos rompería
 * la semántica de eval directo (acceso al ámbito local) y la identidad de Function.
 * Sus usos quedan cubiertos por CSP (unsafe-eval) y por RuntimeMonitor.
 */
export const SinkSpecs: readonly SinkSpec[] = [
  {
    Sink: "innerHTML",
    Owner: OnElement,
    Key: "innerHTML",
    Part: "setter",
    Analyze: MarkupAt(0, TagOf),
  },
  {
    Sink: "innerHTML",
    Owner: (window) => (window.ShadowRoot as typeof ShadowRoot | undefined)?.prototype,
    Key: "innerHTML",
    Part: "setter",
    Analyze: MarkupAt(0, () => "#shadow-root"),
  },
  {
    Sink: "outerHTML",
    Owner: OnElement,
    Key: "outerHTML",
    Part: "setter",
    Analyze: MarkupAt(0, TagOf),
  },
  {
    Sink: "insertAdjacentHTML",
    Owner: OnElement,
    Key: "insertAdjacentHTML",
    Part: "value",
    Analyze: MarkupAt(1, TagOf),
  },
  ...(["write", "writeln"] as const).map((key): SinkSpec => ({
    Sink: "document.write",
    Owner: (window) => window.Document.prototype,
    Key: key,
    Part: "value",
    Analyze: (_thisArg, args, pageHref) => {
      const markup = args.filter((arg): arg is string => typeof arg === "string").join("");
      const indicators = AnalyzeMarkup(markup, pageHref);
      return indicators ? { Indicators: indicators, Target: null, Length: markup.length } : null;
    },
  })),
  {
    Sink: "createContextualFragment",
    Owner: (window) => (window.Range as typeof Range | undefined)?.prototype,
    Key: "createContextualFragment",
    Part: "value",
    Analyze: MarkupAt(0, () => null),
  },
  {
    Sink: "srcdoc",
    Owner: (window) =>
      (window.HTMLIFrameElement as typeof HTMLIFrameElement | undefined)?.prototype,
    Key: "srcdoc",
    Part: "setter",
    Analyze: MarkupAt(0, () => "iframe"),
  },
  {
    Sink: "setAttribute",
    Owner: OnElement,
    Key: "setAttribute",
    Part: "value",
    Analyze: (thisArg, args, pageHref) => {
      const [name, value] = args;
      if (typeof name !== "string" || typeof value !== "string") {
        return null;
      }
      const indicators = AnalyzeAttribute(name, value, pageHref);
      return indicators
        ? {
            Indicators: indicators,
            Target: `${TagOf(thisArg) ?? "element"}[${name.toLowerCase()}]`,
            Length: value.length,
          }
        : null;
    },
  },
  ...(["setTimeout", "setInterval"] as const).map((key): SinkSpec => ({
    Sink: key,
    Owner: (window) => window,
    Key: key,
    Part: "value",
    Analyze: CodeString(),
  })),
];

/**
 * Observa escrituras con indicadores de riesgo en sinks de DOM XSS.
 *
 * Rendimiento: estas APIs se usan con mucha frecuencia (los frameworks asignan
 * innerHTML y setAttribute constantemente). Por eso el análisis corre como prefiltro
 * (Inspect): si no hay indicadores, la llamada continúa sin hook, sin evento y sin
 * capturar stack. Las escrituras equivalentes repetidas se agrupan durante
 * SinkDedupeWindowMs para que un bucle de renderizado no inunde el historial.
 *
 * Privacidad: nunca se registra el contenido escrito.
 */
export class SinkMonitor extends BaseMonitor {
  public readonly Name = "SinkMonitor";
  private Patches: FunctionPatch<SinkData>[] = [];
  private readonly Recent = new Map<string, number>();
  /** Lectura perezosa de la URL: solo se consulta si ya se encontraron indicadores. */
  private readonly ReadHref = (): string => this.Context.GetBaseUrl();

  protected OnStart(): boolean {
    const window = this.Context.Window;
    for (const spec of SinkSpecs) {
      const owner = this.SafeOwner(spec, window);
      if (!owner) {
        continue;
      }
      const patch = new FunctionPatch<SinkData>(
        owner,
        spec.Key,
        {
          CaptureStack: true,
          Inspect: (thisArg, args) => this.Inspect(spec, thisArg, args),
          BeforeApply: (_thisArg, _args, stack, data) => {
            this.Context.Emit("dom.sink", this.Name, data, stack);
          },
        },
        this.Context,
        spec.Part,
      );
      if (patch.Apply()) {
        this.Patches.push(patch);
      }
    }
    return this.Patches.length > 0;
  }

  protected OnStop(): void {
    for (const patch of this.Patches.reverse()) {
      patch.Restore();
    }
    this.Patches = [];
    this.Recent.clear();
  }

  private SafeOwner(spec: SinkSpec, window: SinkWindow): object | undefined {
    try {
      return spec.Owner(window);
    } catch {
      return undefined;
    }
  }

  private Inspect(spec: SinkSpec, thisArg: unknown, args: readonly unknown[]): SinkData | null {
    const result = spec.Analyze(thisArg, args, this.ReadHref);
    if (!result) {
      return null;
    }
    const data: SinkData = { Sink: spec.Sink, ...result };
    return this.IsDuplicate(data) ? null : data;
  }

  private IsDuplicate(data: SinkData): boolean {
    const key = `${data.Sink}|${data.Target ?? ""}|${data.Indicators.join(",")}`;
    const now = Date.now();
    const last = this.Recent.get(key);
    if (last !== undefined && now - last < SinkDedupeWindowMs) {
      return true;
    }
    // Reinsertar mantiene el orden por uso reciente para descartar las más antiguas.
    this.Recent.delete(key);
    this.Recent.set(key, now);
    if (this.Recent.size > MaxDedupeEntries) {
      const oldest = this.Recent.keys().next().value;
      if (oldest !== undefined) {
        this.Recent.delete(oldest);
      }
    }
    return false;
  }
}
