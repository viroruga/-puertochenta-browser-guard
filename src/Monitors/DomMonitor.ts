import type { DomElementData, ObservedTagName } from "../Types/SecurityEvent";
import { DescribeUrl } from "../Utils/UrlUtils";
import { BaseMonitor } from "./BaseMonitor";

const ObservedTags: ReadonlySet<string> = new Set(["SCRIPT", "IFRAME", "OBJECT", "EMBED"]);
const ObservedSelector = "script,iframe,object,embed";

/**
 * Observa la inserción de elementos script, iframe, object y embed.
 *
 * Rendimiento:
 * - MutationObserver solo con childList + subtree; no se observan atributos
 *   ni texto (sería muy costoso en aplicaciones con mucho renderizado).
 * - Para subárboles insertados se usa un único querySelectorAll, y solo si el
 *   nodo tiene hijos elemento.
 * - No se captura stack: el callback es asíncrono y no conserva el origen de la
 *   inserción, por lo que el costo no aportaría información útil.
 *
 * Privacidad: de los scripts inline solo se registra la longitud, nunca el contenido.
 */
export class DomMonitor extends BaseMonitor {
  public readonly Name = "DomMonitor";
  private Observer: MutationObserver | null = null;

  protected OnStart(): boolean {
    const window = this.Context.Window;
    if (typeof (window.MutationObserver as typeof MutationObserver | undefined) !== "function") {
      return false;
    }
    this.Observer = new window.MutationObserver((records) => {
      this.Context.Safely(() => {
        this.OnMutations(records);
      });
    });
    this.Observer.observe(window.document, { childList: true, subtree: true });
    return true;
  }

  protected OnStop(): void {
    if (this.Observer) {
      this.Observer.takeRecords();
      this.Observer.disconnect();
      this.Observer = null;
    }
  }

  private OnMutations(records: readonly MutationRecord[]): void {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (node.nodeType !== 1) {
          continue;
        }
        const element = node as Element;
        if (ObservedTags.has(element.tagName)) {
          this.Inspect(element);
        }
        if (element.firstElementChild !== null) {
          for (const child of element.querySelectorAll(ObservedSelector)) {
            this.Inspect(child);
          }
        }
      }
    }
  }

  private Inspect(element: Element): void {
    this.Context.Emit("dom.element-inserted", this.Name, this.Describe(element));
  }

  /**
   * Extrae los datos relevantes de un elemento, sin leer contenido sensible.
   */
  private Describe(element: Element): DomElementData {
    const tagName = element.tagName.toLowerCase() as ObservedTagName;
    const sourceAttribute = tagName === "object" ? "data" : "src";
    const rawSource = element.getAttribute(sourceAttribute);
    const parserInserted = this.Context.Window.document.readyState === "loading";

    const data: DomElementData = {
      TagName: tagName,
      Src: null,
      Origin: null,
      Scheme: null,
      Inline: rawSource === null || rawSource.trim() === "",
      ParserInserted: parserInserted,
    };

    if (!data.Inline && rawSource !== null) {
      const described = DescribeUrl(rawSource, this.Context.Window.document.baseURI);
      data.Src = described.Url;
      data.Origin = described.Origin;
      data.Scheme = described.Scheme;
    } else if (tagName === "script") {
      data.InlineLength = element.textContent.length;
    } else if (tagName === "iframe") {
      data.InlineLength = element.getAttribute("srcdoc")?.length ?? 0;
    }

    if (tagName === "script") {
      const script = element as HTMLScriptElement;
      data.Type = script.type;
      data.Async = script.async;
      data.Defer = script.defer;
      data.Integrity = script.integrity;
      data.CrossOrigin = script.crossOrigin;
    }

    return data;
  }
}
