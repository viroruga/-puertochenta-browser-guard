import { FunctionPatch } from "../Core/FunctionPatch";
import { BaseMonitor } from "./BaseMonitor";
import { CreateNetworkRequestData, ReadTargetUrl } from "./NetworkEventFactory";

/**
 * Observa llamadas a window.fetch y emite `network.request` (transporte "fetch"), que
 * consumen NetworkDetector y BotDetector.
 *
 * La interceptación es transparente: argumentos, `this`, Promise, valor de retorno
 * y errores se preservan (ver FunctionPatch). Solo se registran URL saneada,
 * método, origen y stack; nunca headers, cookies ni cuerpo.
 *
 * Única excepción a "solo observar": si el anti-scraping lo habilita (opt-in), agrega
 * el header de veredicto a la solicitud (ver AddRequestHeader).
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
        // FunctionPatch ejecuta BeforeApply antes que TransformArgs: el evento describe
        // la llamada original de la aplicación, no la modificada.
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
   * Retorna null para dejar la llamada intacta.
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
    // Igual que fetch(): init.headers reemplaza a los del Request; si no hay, se parte de
    // los headers del Request para no perderlos al pasar un init nuevo.
    const headers = new window.Headers(
      initObject?.headers ?? (isRequest ? input.headers : undefined),
    );
    if (headers.has(header[0])) {
      return null;
    }
    headers.set(header[0], header[1]);
    // Nota: la copia por spread solo conserva propiedades propias enumerables del init.
    return [input, { ...initObject, headers }, ...rest];
  }

  /**
   * Emite el evento de la solicitud. El método sigue la precedencia de fetch():
   * init.method, luego el del Request, y por defecto GET.
   */
  private OnFetch(args: readonly unknown[], stack: string | undefined): void {
    const window = this.Context.Window;
    const [input, init] = args;
    const isRequest = typeof window.Request === "function" && input instanceof window.Request;

    let method = isRequest ? input.method : "GET";
    if (typeof init === "object" && init !== null) {
      // Se valida el tipo: un init hostil podría traer cualquier valor en `method`.
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
