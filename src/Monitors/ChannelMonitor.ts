import { FunctionPatch } from "../Core/FunctionPatch";
import type { NetworkTransport } from "../Types/SecurityEvent";
import { BaseMonitor } from "./BaseMonitor";
import { CreateNetworkRequestData, ReadTargetUrl } from "./NetworkEventFactory";

type ChannelWindow = Window & typeof globalThis;

/** Destino extraído de una llamada: URL sin sanear (null = la propia página) y método. */
interface ChannelTarget {
  Url: string | null;
  Method: string;
}

/**
 * Canal de salida observado mediante interceptación.
 * - Owner: objeto que contiene la API (window o un prototipo); undefined si no existe.
 * - Kind: si se intercepta como llamada (apply) o como constructor (construct).
 * - Read: extrae el destino; retorna null para ignorar la llamada (p. ej. window.open()
 *   sin URL).
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
 *
 * El botón que envía (submitter) tiene prioridad con formaction/formmethod, igual que
 * en el navegador.
 *
 * Nota: usa los constructores globales HTMLFormElement/HTMLElement (los del realm de
 * BrowserGuard), no los del realm observado; un formulario de otro realm no los satisface.
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

/**
 * Lector para APIs cuyo primer argumento es la URL de destino. Una URL vacía o ilegible
 * se ignora (p. ej. window.open() para abrir una ventana en blanco).
 */
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
    // sendBeacon sobrevive al cierre de la página: canal típico de exfiltración.
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
    // La URL de una ventana nueva puede llevar datos en la query.
    Transport: "window-open",
    Owner: (window) => window,
    Key: "open",
    Kind: "apply",
    Read: UrlArgument("GET"),
  },
  {
    // Un service worker registrado persiste e intercepta todo el tráfico del origen.
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
 * Solo genera eventos `network.request`: NetworkDetector decide según el origen de destino
 * (y BotDetector los cuenta como actividad de red).
 * Privacidad: nunca se leen cuerpos, campos de formularios ni datos enviados; la URL se
 * sanea como en el resto de monitores de red.
 */
export class ChannelMonitor extends BaseMonitor {
  public readonly Name = "ChannelMonitor";
  private Patches: FunctionPatch[] = [];
  /** Documento donde se registró el listener de "submit", para retirarlo en OnStop. */
  private SubmitTarget: Document | null = null;

  /**
   * Envíos iniciados por el usuario o por requestSubmit(). El listener es pasivo y en
   * captura: corre antes que los handlers de la aplicación, por lo que también reporta
   * envíos que luego se cancelan con preventDefault() (p. ej. formularios de una SPA).
   */
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
      // API inexistente en este navegador: se omite ese canal sin afectar a los demás.
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
      // Un canal no interceptable (p. ej. propiedad no configurable) no impide el resto.
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
    // Orden inverso al de instalación, para deshacer correctamente cadenas de wrappers.
    for (const patch of this.Patches.reverse()) {
      patch.Restore();
    }
    this.Patches = [];
    this.SubmitTarget?.removeEventListener("submit", this.OnSubmit, { capture: true });
    this.SubmitTarget = null;
  }

  /** Resuelve el Owner de un canal; un getter hostil o una API ausente no debe lanzar. */
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
