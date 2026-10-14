import { FunctionPatch } from "../Core/FunctionPatch";
import { BaseMonitor } from "./BaseMonitor";
import { CreateNetworkRequestData, ReadTargetUrl } from "./NetworkEventFactory";

/**
 * Observa la creación de conexiones mediante `new WebSocket()` y emite `network.request`
 * (transporte "websocket"), que consumen NetworkDetector y BotDetector.
 *
 * El constructor se intercepta con un Proxy, por lo que `instanceof WebSocket`,
 * las constantes estáticas (OPEN, CLOSED, ...) y las subclases siguen funcionando.
 *
 * Privacidad: la URL se sanea (los tokens suelen viajar en la query de la conexión) y
 * solo se registran los subprotocolos declarados.
 *
 * En esta versión no se inspeccionan mensajes. Para hacerlo en el futuro, el hook
 * BeforeConstruct puede ampliarse a un AfterConstruct que reciba la instancia y
 * agregue listeners pasivos de "message"/"send" sin alterar este contrato.
 */
export class WebSocketMonitor extends BaseMonitor {
  public readonly Name = "WebSocketMonitor";
  private Patch: FunctionPatch | null = null;

  protected OnStart(): boolean {
    const window = this.Context.Window;
    if (typeof (window.WebSocket as typeof WebSocket | undefined) !== "function") {
      return false;
    }
    this.Patch = new FunctionPatch(
      window,
      "WebSocket",
      {
        CaptureStack: true,
        BeforeConstruct: (args, stack) => {
          this.OnConstruct(args, stack);
        },
      },
      this.Context,
    );
    return this.Patch.Apply();
  }

  protected OnStop(): void {
    this.Patch?.Restore();
    this.Patch = null;
  }

  private OnConstruct(args: readonly unknown[], stack: string | undefined): void {
    const [url, protocols] = args;
    // El segundo argumento puede ser un string o un array; se descartan los no-string
    // para no convertir objetos arbitrarios (ejecutaría su toString()).
    const protocolList =
      typeof protocols === "string"
        ? [protocols]
        : Array.isArray(protocols)
          ? protocols.filter((protocol): protocol is string => typeof protocol === "string")
          : [];

    this.Context.Emit(
      "network.request",
      this.Name,
      CreateNetworkRequestData(this.Context, "websocket", ReadTargetUrl(url, this.Context.Window), {
        Protocols: protocolList,
      }),
      stack,
    );
  }
}
