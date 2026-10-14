import { BaseMonitor } from "./BaseMonitor";
import { CreateNetworkRequestData } from "./NetworkEventFactory";

/**
 * Tipos de iniciador que ya cubren otros monitores (con stack trace): se omiten para no
 * duplicar hallazgos. "script" lo cubre DomMonitor (scripts insertados dinámicamente);
 * "fetch"/"xmlhttprequest"/"beacon", FetchMonitor, XhrMonitor y ChannelMonitor.
 */
const CoveredInitiators: ReadonlySet<string> = new Set([
  "fetch",
  "xmlhttprequest",
  "beacon",
  "script",
]);

/**
 * Observa la carga de recursos (imágenes, CSS, fuentes, medios, iframes...) mediante
 * PerformanceObserver y emite `network.request` (transporte "resource"), que consumen
 * NetworkDetector y BotDetector.
 *
 * Por qué PerformanceObserver: no modifica ninguna API de la página y cubre cualquier
 * forma de iniciar la carga (new Image().src = ..., HTML insertado, CSS url(), ...),
 * que es como suele exfiltrarse información sin fetch/XHR. No ofrece stack trace.
 *
 * Solo se observan recursos cargados después de Start() (sin el buffer previo): los
 * recursos de la carga inicial forman parte de la página, no de un comportamiento nuevo.
 *
 * Privacidad: `entry.name` es la URL completa; se sanea igual que el resto de eventos de
 * red (sin query ni fragmento, solo su longitud).
 */
export class ResourceMonitor extends BaseMonitor {
  public readonly Name = "ResourceMonitor";
  private Observer: PerformanceObserver | null = null;

  protected OnStart(): boolean {
    const window = this.Context.Window;
    const ObserverConstructor = window.PerformanceObserver as
      typeof PerformanceObserver | undefined;
    // supportedEntryTypes no existe en navegadores antiguos.
    const supported = (
      ObserverConstructor as { supportedEntryTypes?: readonly string[] } | undefined
    )?.supportedEntryTypes;
    if (typeof ObserverConstructor !== "function" || !supported?.includes("resource")) {
      return false;
    }
    this.Observer = new ObserverConstructor((list) => {
      this.Context.Safely(() => {
        this.OnEntries(list.getEntries());
      });
    });
    this.Observer.observe({ type: "resource", buffered: false });
    return true;
  }

  protected OnStop(): void {
    this.Observer?.disconnect();
    this.Observer = null;
  }

  private OnEntries(entries: readonly PerformanceEntry[]): void {
    for (const entry of entries) {
      const initiator = (entry as PerformanceResourceTiming).initiatorType;
      if (CoveredInitiators.has(initiator)) {
        continue;
      }
      // Sin stack: el callback del observer es asíncrono y no conserva quién inició la carga.
      this.Context.Emit(
        "network.request",
        this.Name,
        CreateNetworkRequestData(this.Context, "resource", entry.name, {
          InitiatorType: initiator,
        }),
      );
    }
  }
}
