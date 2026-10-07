import { FunctionPatch } from "../Core/FunctionPatch";
import { BaseMonitor } from "./BaseMonitor";
import { CreateNetworkRequestData, ReadTargetUrl } from "./NetworkEventFactory";

interface PendingRequest {
  Method: string;
  Url: string | null;
}

/**
 * Observa XMLHttpRequest.prototype.open y XMLHttpRequest.prototype.send.
 *
 * open() solo registra método y URL en un WeakMap (sin fugas de memoria: la entrada
 * desaparece con la instancia). El evento se emite en send(), que es cuando la
 * solicitud realmente sale; así el stack apunta al código que la envía.
 */
export class XhrMonitor extends BaseMonitor {
  public readonly Name = "XhrMonitor";
  private Patches: FunctionPatch[] = [];
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
        // open() no necesita stack: el evento se emite en send().
        CaptureStack: true,
        BeforeApply: (thisArg, _args, stack) => {
          this.OnSend(thisArg, stack);
        },
      },
      this.Context,
    );

    this.Patches = [openPatch, sendPatch];
    return openPatch.Apply() && sendPatch.Apply();
  }

  protected OnStop(): void {
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
