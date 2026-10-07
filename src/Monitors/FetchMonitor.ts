import { FunctionPatch } from "../Core/FunctionPatch";
import { BaseMonitor } from "./BaseMonitor";
import { CreateNetworkRequestData, ReadTargetUrl } from "./NetworkEventFactory";

/**
 * Observa llamadas a window.fetch.
 *
 * La interceptación es transparente: argumentos, `this`, Promise, valor de retorno
 * y errores se preservan (ver FunctionPatch). Solo se registran URL saneada,
 * método, origen y stack; nunca headers, cookies ni cuerpo.
 */
export class FetchMonitor extends BaseMonitor {
  public readonly Name = "FetchMonitor";
  private Patch: FunctionPatch | null = null;

  protected OnStart(): boolean {
    const window = this.Context.Window;
    if (typeof window.fetch !== "function") {
      return false;
    }
    this.Patch = new FunctionPatch(
      window,
      "fetch",
      {
        CaptureStack: true,
        BeforeApply: (_thisArg, args, stack) => {
          this.OnFetch(args, stack);
        },
        TransformArgs: (_thisArg, args) => this.AddRequestHeader(args),
      },
      this.Context,
    );
    return this.Patch.Apply();
  }

  protected OnStop(): void {
    this.Patch?.Restore();
    this.Patch = null;
  }

  /**
   * Agrega el header de veredicto anti-scraping cuando corresponde (opt-in).
   * No modifica los objetos de la aplicación: crea un RequestInit y unos Headers nuevos
   * que conservan los headers originales. Si la aplicación ya definió el header, se respeta.
   */
  private AddRequestHeader(args: readonly unknown[]): unknown[] | null {
    const window = this.Context.Window;
    const [input, init, ...rest] = args;
    const header = this.Context.GetRequestHeader(ReadTargetUrl(input, window));
    if (!header || typeof window.Headers !== "function") {
      return null;
    }
    const isRequest = typeof window.Request === "function" && input instanceof window.Request;
    const initObject = typeof init === "object" && init !== null ? (init as RequestInit) : null;
    const headers = new window.Headers(
      initObject?.headers ?? (isRequest ? input.headers : undefined),
    );
    if (headers.has(header[0])) {
      return null;
    }
    headers.set(header[0], header[1]);
    return [input, { ...initObject, headers }, ...rest];
  }

  private OnFetch(args: readonly unknown[], stack: string | undefined): void {
    const window = this.Context.Window;
    const [input, init] = args;
    const isRequest = typeof window.Request === "function" && input instanceof window.Request;

    let method = isRequest ? input.method : "GET";
    if (typeof init === "object" && init !== null) {
      const initMethod = (init as { method?: unknown }).method;
      if (typeof initMethod === "string") {
        method = initMethod;
      }
    }

    this.Context.Emit(
      "network.request",
      this.Name,
      CreateNetworkRequestData(this.Context, "fetch", ReadTargetUrl(input, window), {
        Method: method,
      }),
      stack,
    );
  }
}
