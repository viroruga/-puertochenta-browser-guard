import { FunctionPatch } from "../Core/FunctionPatch";
import type { NetworkTransport } from "../Types/SecurityEvent";
import { BaseMonitor } from "./BaseMonitor";
import { CreateNetworkRequestData, ReadTargetUrl } from "./NetworkEventFactory";

type ChannelWindow = Window & typeof globalThis;

interface ChannelTarget {
  Url: string | null;
  Method: string;
}

/**
 * Canal de salida observado mediante interceptación.
 * Read retorna null para ignorar la llamada (p. ej. window.open() sin URL).
 */
interface ChannelSpec {
  Transport: NetworkTransport;
  Owner: (window: ChannelWindow) => object | undefined;
  Key: string;
  Kind: "apply" | "construct";
  Read: (thisArg: unknown, args: readonly unknown[], window: ChannelWindow) => ChannelTarget | null;
}

/**
 * Destino de un formulario. Se leen los atributos (no las propiedades `action`/`method`,
 * que un campo con name="action" puede sombrear). Nunca se leen los campos.
 */
export function ReadFormTarget(form: unknown, submitter?: unknown): ChannelTarget | null {
  if (!(form instanceof HTMLFormElement)) {
    return null;
  }
  const button = submitter instanceof HTMLElement ? submitter : null;
  const action = button?.getAttribute("formaction") ?? form.getAttribute("action") ?? "";
  const method = button?.getAttribute("formmethod") ?? form.getAttribute("method") ?? "GET";
  // Sin action, el formulario se envía a la propia página.
  return { Url: action === "" ? null : action, Method: method };
}

function UrlArgument(method: string): ChannelSpec["Read"] {
  return (_thisArg, args, window) => {
    const url = ReadTargetUrl(args[0], window);
    return url === null || url === "" ? null : { Url: url, Method: method };
  };
}

/**
 * Canales observados por interceptación. Todos preservan argumentos, `this` y resultado.
 */
export const ChannelSpecs: readonly ChannelSpec[] = [
  {
    Transport: "beacon",
    Owner: (window) => (window.Navigator as typeof Navigator | undefined)?.prototype,
    Key: "sendBeacon",
    Kind: "apply",
    Read: UrlArgument("POST"),
  },
  {
    Transport: "eventsource",
    Owner: (window) => window,
    Key: "EventSource",
    Kind: "construct",
    Read: UrlArgument("GET"),
  },
  {
    Transport: "window-open",
    Owner: (window) => window,
    Key: "open",
    Kind: "apply",
    Read: UrlArgument("GET"),
  },
  {
    Transport: "service-worker",
    Owner: (window) =>
      (window.ServiceWorkerContainer as typeof ServiceWorkerContainer | undefined)?.prototype,
    Key: "register",
    Kind: "apply",
    Read: UrlArgument("GET"),
  },
  {
    // submit() no dispara el evento "submit": se intercepta.
    Transport: "form",
    Owner: (window) => (window.HTMLFormElement as typeof HTMLFormElement | undefined)?.prototype,
    Key: "submit",
    Kind: "apply",
    Read: (thisArg) => ReadFormTarget(thisArg),
  },
];

/**
 * Observa canales de salida de datos distintos de fetch/XHR/WebSocket: sendBeacon,
 * EventSource, window.open, envío de formularios y registro de service workers.
 *
 * Solo genera eventos de red: NetworkDetector decide según el origen de destino.
 * Privacidad: nunca se leen cuerpos, campos de formularios ni datos enviados.
 */
export class ChannelMonitor extends BaseMonitor {
  public readonly Name = "ChannelMonitor";
  private Patches: FunctionPatch[] = [];
  private SubmitTarget: Document | null = null;

  private readonly OnSubmit = (event: Event): void => {
    this.Context.Safely(() => {
      const target = ReadFormTarget(event.target, (event as SubmitEvent).submitter);
      if (target) {
        this.EmitChannel("form", target);
      }
    });
  };

  protected OnStart(): boolean {
    const window = this.Context.Window;
    for (const spec of ChannelSpecs) {
      const owner = this.SafeOwner(spec, window);
      if (!owner) {
        continue;
      }
      const emit = (
        thisArg: unknown,
        args: readonly unknown[],
        stack: string | undefined,
      ): void => {
        const target = spec.Read(thisArg, args, window);
        if (target) {
          this.EmitChannel(spec.Transport, target, stack);
        }
      };
      const patch = new FunctionPatch(
        owner,
        spec.Key,
        spec.Kind === "apply"
          ? { CaptureStack: true, BeforeApply: emit }
          : {
              CaptureStack: true,
              BeforeConstruct: (args, stack) => {
                emit(undefined, args, stack);
              },
            },
        this.Context,
      );
      if (patch.Apply()) {
        this.Patches.push(patch);
      }
    }

    // Envíos iniciados por el usuario o por requestSubmit(): evento "submit" (pasivo).
    window.document.addEventListener("submit", this.OnSubmit, { capture: true, passive: true });
    this.SubmitTarget = window.document;
    return true;
  }

  protected OnStop(): void {
    for (const patch of this.Patches.reverse()) {
      patch.Restore();
    }
    this.Patches = [];
    this.SubmitTarget?.removeEventListener("submit", this.OnSubmit, { capture: true });
    this.SubmitTarget = null;
  }

  private SafeOwner(spec: ChannelSpec, window: ChannelWindow): object | undefined {
    try {
      return spec.Owner(window);
    } catch {
      return undefined;
    }
  }

  private EmitChannel(transport: NetworkTransport, target: ChannelTarget, stack?: string): void {
    // Sin URL (formulario sin action) el destino es la propia página.
    const url = target.Url ?? this.Context.GetBaseUrl();
    this.Context.Emit(
      "network.request",
      this.Name,
      CreateNetworkRequestData(this.Context, transport, url, { Method: target.Method }),
      stack,
    );
  }
}
