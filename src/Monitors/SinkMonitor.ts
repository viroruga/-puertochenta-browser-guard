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
 * Nunca debe devolver el contenido analizado, solo indicadores, objetivo y longitud.
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

/** Etiqueta en minúsculas del elemento, o null si `thisArg` no parece un elemento. */
function TagOf(element: unknown): string | null {
  return typeof (element as Element | null)?.tagName === "string"
    ? (element as Element).tagName.toLowerCase()
    : null;
}

/**
 * Analiza como HTML el argumento en la posición `index` (0 para setters, 1 para
 * insertAdjacentHTML(position, html)). `target` describe el objetivo del evento.
 */
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

/** Analiza el primer argumento de setTimeout/setInterval cuando es código como string. */
function CodeString(): SinkSpec["Analyze"] {
  return (_thisArg, args, pageHref) => {
    const code = args[0];
    // Solo el código como string es un sink (se evalúa como eval); una función es el uso
    // normal. Siempre se reporta: AnalyzeCode incluye al menos el indicador "string-code".
    return typeof code === "string" && code.trim() !== ""
      ? { Indicators: AnalyzeCode(code, pageHref), Target: null, Length: code.length }
      : null;
  };
}

/** Owner de los sinks definidos en Element.prototype. */
const OnElement = (window: SinkWindow): object => window.Element.prototype;

/**
 * Propiedad URL de un elemento donde "javascript:" ejecuta código (a.href = ..., etc.).
 * El nombre del sink coincide con el de la propiedad interceptada; `attribute` es el
 * nombre del atributo HTML equivalente, que es lo que analiza AnalyzeAttribute.
 * El constructor se busca por nombre en el realm porque algunos pueden no existir.
 */
function UrlProperty(sink: SinkName, constructorName: string, attribute: string): SinkSpec {
  return {
    Sink: sink,
    Owner: (window) =>
      (window as unknown as Record<string, { prototype?: object } | undefined>)[constructorName]
        ?.prototype,
    Key: sink,
    Part: "setter",
    Analyze: (thisArg, args, pageHref) => {
      const value = args[0];
      if (typeof value !== "string") {
        return null;
      }
      const indicators = AnalyzeAttribute(attribute, value, pageHref);
      return indicators
        ? { Indicators: indicators, Target: TagOf(thisArg), Length: value.length }
        : null;
    },
  };
}

/**
 * Sinks observados. eval y new Function se omiten a propósito: interceptarlos rompería
 * la semántica de eval directo (acceso al ámbito local) y la identidad de Function.
 * Sus usos solo quedan cubiertos por CSP (unsafe-eval → CspMonitor); RuntimeMonitor
 * vigila que no se reemplacen, no que se invoquen.
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
    // ShadowRoot define su propio innerHTML (no hereda de Element).
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
      // write() acepta varios argumentos que se concatenan; los no-string (TrustedHTML)
      // se omiten porque ya pasaron por una política.
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
      // Qué atributos son peligrosos (on*, href="javascript:...", ...) lo decide
      // AnalyzeAttribute; aquí solo se descartan valores no string.
      if (typeof name !== "string" || typeof value !== "string") {
        return null;
      }
      const indicators = AnalyzeAttribute(name, value, pageHref);
      return indicators
        ? {
            Indicators: indicators,
            // Formato "tag[atributo]", p. ej. "img[onerror]".
            Target: `${TagOf(thisArg) ?? "element"}[${name.toLowerCase()}]`,
            Length: value.length,
          }
        : null;
    },
  },
  UrlProperty("href", "HTMLAnchorElement", "href"),
  UrlProperty("href", "HTMLAreaElement", "href"),
  UrlProperty("src", "HTMLIFrameElement", "src"),
  UrlProperty("src", "HTMLEmbedElement", "src"),
  UrlProperty("data", "HTMLObjectElement", "data"),
  UrlProperty("action", "HTMLFormElement", "action"),
  UrlProperty("formAction", "HTMLButtonElement", "formaction"),
  UrlProperty("formAction", "HTMLInputElement", "formaction"),
  ...(["setTimeout", "setInterval"] as const).map((key): SinkSpec => ({
    Sink: key,
    Owner: (window) => window,
    Key: key,
    Part: "value",
    Analyze: CodeString(),
  })),
];

/**
 * Observa escrituras con indicadores de riesgo en sinks de DOM XSS y emite `dom.sink`,
 * que consume XssSinkDetector.
 *
 * Rendimiento: estas APIs se usan con mucha frecuencia (los frameworks asignan
 * innerHTML y setAttribute constantemente). Por eso el análisis corre como prefiltro
 * (Inspect): si no hay indicadores, la llamada continúa sin hook, sin evento y sin
 * capturar stack. Las escrituras equivalentes repetidas se agrupan durante
 * SinkDedupeWindowMs para que un bucle de renderizado no inunde el historial.
 *
 * Privacidad: nunca se registra el contenido escrito; solo el sink, el objetivo, la
 * longitud y los nombres de los indicadores.
 */
export class SinkMonitor extends BaseMonitor {
  public readonly Name = "SinkMonitor";
  private Patches: FunctionPatch<SinkData>[] = [];
  /** Clave de deduplicación → último momento reportado (orden de inserción = LRU). */
  private readonly Recent = new Map<string, number>();
  /** Lectura perezosa de la URL: solo se consulta si ya se encontraron indicadores. */
  private readonly ReadHref = (): string => this.Context.GetPageUrl();

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
          // El stack solo se captura cuando Inspect encontró algo (ver FunctionPatch).
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
    // Basta con un sink interceptado; los que no existen en este navegador se omiten.
    return this.Patches.length > 0;
  }

  protected OnStop(): void {
    for (const patch of this.Patches.reverse()) {
      patch.Restore();
    }
    this.Patches = [];
    this.Recent.clear();
  }

  /** Resuelve el Owner de un sink; un getter hostil o una API ausente no debe lanzar. */
  private SafeOwner(spec: SinkSpec, window: SinkWindow): object | undefined {
    try {
      return spec.Owner(window);
    } catch {
      return undefined;
    }
  }

  /**
   * Prefiltro de FunctionPatch: retorna los datos del evento o null para dejar pasar la
   * llamada sin costo adicional (sin indicadores o duplicada).
   */
  private Inspect(spec: SinkSpec, thisArg: unknown, args: readonly unknown[]): SinkData | null {
    const result = spec.Analyze(thisArg, args, this.ReadHref);
    if (!result) {
      return null;
    }
    const data: SinkData = { Sink: spec.Sink, ...result };
    return this.IsDuplicate(data) ? null : data;
  }

  /**
   * Indica si una escritura equivalente (mismo sink, objetivo e indicadores) ya se
   * reportó dentro de SinkDedupeWindowMs. Si no, la registra como la más reciente.
   */
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
