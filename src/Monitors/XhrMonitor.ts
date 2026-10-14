import { FunctionPatch } from "../Core/FunctionPatch";
import { BaseMonitor } from "./BaseMonitor";
import { CreateNetworkRequestData, ReadTargetUrl } from "./NetworkEventFactory";

/** Datos de open() guardados hasta que la solicitud se envía con send(). */
interface PendingRequest {
  Method: string;
  /** URL sin sanear (se sanea al emitir); null si no se pudo leer sin ejecutar código. */
  Url: string | null;
}

/**
 * Observa XMLHttpRequest.prototype.open y XMLHttpRequest.prototype.send y emite
 * `network.request` (transporte "xhr"), que consumen NetworkDetector y BotDetector.
 *
 * open() solo registra método y URL en un WeakMap (sin fugas de memoria: la entrada
 * desaparece con la instancia). El evento se emite en send(), que es cuando la
 * solicitud realmente sale; así el stack apunta al código que la envía.
 *
 * Privacidad: nunca se leen el cuerpo de send(), los headers ni la respuesta.
 */
export class XhrMonitor extends BaseMonitor {
  public readonly Name = "XhrMonitor";
  private Patches: FunctionPatch[] = [];
  /** Instancia de XHR → datos de su último open(). */
  private Requests = new WeakMap<object, PendingRequest>();

  protected OnStart(): boolean {
    const window = this.Context.Window;
    const prototype = (window.XMLHttpRequest as typeof XMLHttpRequest | undefined)?.prototype;
    if (!prototype) {
      return false;
    }

    const openPatch = new FunctionPatch(
      prototype,
      "open",
      {
        // open() no necesita stack: el evento se emite en send().
        BeforeApply: (thisArg, args) => {
          this.OnOpen(thisArg, args);
        },
      },
      this.Context,
    );
    const sendPatch = new FunctionPatch(
      prototype,
      "send",
      {
        CaptureStack: true,
        BeforeApply: (thisArg, _args, stack) => {
          this.OnSend(thisArg, stack);
        },
      },
      this.Context,
    );

    this.Patches = [openPatch, sendPatch];
    // Si open no se puede interceptar, send no tendría datos: se exige ambos. Ante un
    // fallo, BaseMonitor invoca OnStop y se restaura lo instalado.
    return openPatch.Apply() && sendPatch.Apply();
  }

  protected OnStop(): void {
    // Orden inverso al de instalación, para deshacer correctamente cadenas de wrappers.
    for (const patch of this.Patches.reverse()) {
      patch.Restore();
    }
    this.Patches = [];
    this.Requests = new WeakMap();
  }

  private OnOpen(thisArg: unknown, args: readonly unknown[]): void {
    if (typeof thisArg !== "object" || thisArg === null) {
      return;
    }
    const [method, url] = args;
    this.Requests.set(thisArg, {
      Method: typeof method === "string" ? method : "GET",
      Url: ReadTargetUrl(url, this.Context.Window),
    });
  }

  private OnSend(thisArg: unknown, stack: string | undefined): void {
    if (typeof thisArg !== "object" || thisArg === null) {
      return;
    }
    // Sin open() previo observado (p. ej. abierto antes de Start) no hay nada que reportar;
    // send() fallará igualmente si la instancia no está abierta.
    const request = this.Requests.get(thisArg);
    if (!request) {
      return;
    }
    this.Context.Emit(
      "network.request",
      this.Name,
      CreateNetworkRequestData(this.Context, "xhr", request.Url, { Method: request.Method }),
      stack,
    );

    // Header de veredicto anti-scraping (opt-in). send() aún no se ejecutó, por lo que
    // la solicitud sigue en estado OPENED y acepta headers.
    const header = this.Context.GetRequestHeader(request.Url);
    if (header) {
      this.Context.Safely(() => {
        (thisArg as XMLHttpRequest).setRequestHeader(header[0], header[1]);
      });
    }
  }
}
