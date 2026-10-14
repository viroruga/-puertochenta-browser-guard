import { FunctionPatch } from "../Core/FunctionPatch";
import type { GuardContext } from "../Core/GuardContext";
import type { ResolvedConfig } from "../Types/BrowserGuardConfig";
import type { Monitor } from "../Types/Monitor";
import type { RealmAccessData } from "../Types/SecurityEvent";
import { DescribeUrl } from "../Utils/UrlUtils";
import { BaseMonitor } from "./BaseMonitor";
import { ChannelMonitor } from "./ChannelMonitor";
import { FetchMonitor } from "./FetchMonitor";
import { ResourceMonitor } from "./ResourceMonitor";
import { SinkMonitor } from "./SinkMonitor";
import { WebSocketMonitor } from "./WebSocketMonitor";
import { XhrMonitor } from "./XhrMonitor";

type RealmWindow = Window & typeof globalThis;

/** Realms protegidos simultáneamente como máximo (memoria acotada). */
export const MaxGuardedRealms = 20;

/** Realm protegido y los monitores instalados en él (para detenerlos después). */
interface GuardedRealm {
  Window: RealmWindow;
  Monitors: Monitor[];
}

/**
 * Monitores que se replican en cada realm del mismo origen, según la configuración: el
 * interruptor de `Config.Monitors` que los habilita y su fábrica.
 *
 * Solo los que cubren canales de salida y sinks: los monitores de integridad
 * (Prototype/Runtime) y DomMonitor siguen observando únicamente el realm principal.
 */
const RealmMonitorFactories: readonly (readonly [
  keyof ResolvedConfig["Monitors"],
  (context: GuardContext) => Monitor,
])[] = [
  ["Fetch", (context) => new FetchMonitor(context)],
  ["Xhr", (context) => new XhrMonitor(context)],
  ["WebSocket", (context) => new WebSocketMonitor(context)],
  ["Channels", (context) => new ChannelMonitor(context)],
  ["Channels", (context) => new ResourceMonitor(context)],
  ["Sinks", (context) => new SinkMonitor(context)],
];

/**
 * Indica si se puede acceder al realm (mismo origen). Nunca lanza.
 */
function IsAccessibleRealm(realm: object): boolean {
  try {
    // En un realm de otro origen, leer document lanza SecurityError.
    return (realm as { document?: unknown }).document !== undefined;
  } catch {
    return false;
  }
}

/**
 * Extiende el monitoreo a los iframes del mismo origen y emite `runtime.realm` cuando un
 * script obtiene el realm de un iframe, que consume RuntimeIntegrityDetector.
 *
 * Problema: cada iframe tiene su propio fetch, XMLHttpRequest, innerHTML... Obtener el
 * window de un iframe del mismo origen (típicamente uno vacío, creado al vuelo) es la
 * forma más común de conseguir APIs sin interceptar y evadir un monitor del lado cliente.
 *
 * Solución:
 * - se interceptan los getters contentWindow y contentDocument: antes de devolver el
 *   realm se instalan en él los monitores de red, canales y sinks, y se reporta el acceso;
 * - se observan los iframes insertados, para proteger también los accesos por caminos
 *   que no se pueden interceptar (window.frames[0]) cuando ocurren después.
 *
 * Los realms de otro origen se ignoran (no se pueden observar ni modificar).
 *
 * Los monitores del realm usan un contexto hijo (GuardContext.CreateChild): sus eventos
 * llegan al pipeline principal y sus interceptores se reconocen como propios.
 *
 * Privacidad: del iframe solo se informa "about:blank", "srcdoc" o la URL saneada.
 */
export class RealmMonitor extends BaseMonitor {
  public readonly Name = "RealmMonitor";
  private Patches: FunctionPatch[] = [];
  private Observer: MutationObserver | null = null;
  /** Realms protegidos, del más antiguo al más reciente (se descartan por FIFO). */
  private Guarded: GuardedRealm[] = [];
  /** Realms de otro origen ya comprobados, para no repetir el acceso que lanza. */
  private CrossOrigin = new WeakSet();
  /** Getter original de contentWindow, para leer realms sin disparar el hook propio. */
  private OriginalContentWindow: (() => unknown) | null = null;

  protected OnStart(): boolean {
    const window = this.Context.Window;
    const prototype = (window.HTMLIFrameElement as typeof HTMLIFrameElement | undefined)?.prototype;
    if (!prototype) {
      return false;
    }
    this.OriginalContentWindow =
      // eslint-disable-next-line @typescript-eslint/unbound-method -- Se invoca con call(frame).
      Object.getOwnPropertyDescriptor(prototype, "contentWindow")?.get ?? null;
    // Se interceptan los getters (no los valores): AfterApply recibe el realm que se va a
    // devolver y lo protege antes de que la aplicación pueda usarlo.
    for (const key of ["contentWindow", "contentDocument"] as const) {
      const patch = new FunctionPatch(
        prototype,
        key,
        {
          AfterApply: (frame, result) => {
            const realm =
              key === "contentDocument" ? (result as Document | null)?.defaultView : result;
            // Solo se reporta el primer acceso a cada realm, no cada lectura del getter.
            if (this.Guard(realm) === "guarded-now") {
              this.ReportAccess(frame, key);
            }
          },
        },
        this.Context,
        "getter",
      );
      // Si un getter no es interceptable, se protege igualmente vía MutationObserver.
      if (patch.Apply()) {
        this.Patches.push(patch);
      }
    }

    // Accesos posteriores por window.frames[i]: se protege el iframe al insertarlo.
    this.Observer = new window.MutationObserver((records) => {
      this.Context.Safely(() => {
        this.OnMutations(records);
      });
    });
    this.Observer.observe(window.document, { childList: true, subtree: true });
    return true;
  }

  protected OnStop(): void {
    // Primero se dejan de proteger realms nuevos; luego se restauran los getters y por
    // último se detienen los monitores instalados en cada realm.
    this.Observer?.disconnect();
    this.Observer = null;
    for (const patch of this.Patches.reverse()) {
      patch.Restore();
    }
    this.Patches = [];
    for (const realm of this.Guarded) {
      this.StopRealm(realm);
    }
    this.Guarded = [];
    this.CrossOrigin = new WeakSet();
    this.OriginalContentWindow = null;
  }

  private OnMutations(records: readonly MutationRecord[]): void {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (node.nodeType !== 1) {
          continue;
        }
        const element = node as Element;
        // El iframe puede ser el nodo insertado o estar dentro del subárbol insertado.
        const frames =
          element.tagName === "IFRAME"
            ? [element]
            : element.firstElementChild
              ? [...element.querySelectorAll("iframe")]
              : [];
        for (const frame of frames) {
          // Se lee con el getter original para no reportar este acceso interno.
          this.Guard(this.ReadRealm(frame));
        }
      }
    }
  }

  /**
   * Instala los monitores en el realm si es del mismo origen y aún no está protegido.
   * Nunca lanza para realms de otro origen. Retorna "guarded-now" solo si los instaló en
   * esta llamada.
   */
  private Guard(realm: unknown): "guarded-now" | "skipped" {
    if (
      typeof realm !== "object" ||
      realm === null ||
      realm === this.Context.Window ||
      this.CrossOrigin.has(realm)
    ) {
      return "skipped";
    }
    if (!IsAccessibleRealm(realm)) {
      this.CrossOrigin.add(realm);
      return "skipped";
    }
    const window = realm as RealmWindow;
    // El WindowProxy de un iframe conserva su identidad al navegar, aunque el realm
    // subyacente (y sus APIs) sea nuevo: por eso la búsqueda por identidad no basta.
    const existing = this.Guarded.find((entry) => entry.Window === window);
    if (existing) {
      // Tras una navegación el iframe tiene un realm nuevo: se vuelve a proteger.
      if (existing.Monitors.every((monitor) => this.IsStillPatched(monitor, window))) {
        return "skipped";
      }
      this.StopRealm(existing);
      this.Guarded = this.Guarded.filter((entry) => entry !== existing);
    }

    // Cada monitor se inicia aislado: si uno falla en este realm, el resto sigue activo.
    const child = this.Context.CreateChild(window);
    const monitors = RealmMonitorFactories.filter(
      ([toggle]) => this.Context.Config.Monitors[toggle],
    ).map(([, create]) => create(child));
    for (const monitor of monitors) {
      this.Context.Safely(() => {
        monitor.Start();
      });
    }
    this.Guarded.push({ Window: window, Monitors: monitors });
    // Memoria acotada: se libera el realm más antiguo (sus monitores se detienen). Si se
    // vuelve a acceder a él, se protegerá de nuevo.
    if (this.Guarded.length > MaxGuardedRealms) {
      const oldest = this.Guarded.shift();
      if (oldest) {
        this.StopRealm(oldest);
      }
    }
    return "guarded-now";
  }

  /**
   * Indica si el realm sigue interceptado (no hubo navegación). Solo FetchMonitor sirve
   * de testigo: si window.fetch ya no es el proxy propio, el realm es nuevo. Los demás
   * monitores se consideran vigentes.
   */
  private IsStillPatched(monitor: Monitor, window: RealmWindow): boolean {
    // Solo se compara por identidad con el proxy propio.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    return monitor.Name !== "FetchMonitor" || this.Context.IsOwnFunction(window.fetch);
  }

  /** Detiene los monitores de un realm en orden inverso al de inicio. */
  private StopRealm(realm: GuardedRealm): void {
    for (const monitor of [...realm.Monitors].reverse()) {
      this.Context.Safely(() => {
        monitor.Stop();
      });
    }
  }

  /** Lee contentWindow con el getter original, sin pasar por el interceptor. */
  private ReadRealm(frame: Element): unknown {
    return this.OriginalContentWindow?.call(frame);
  }

  /**
   * Emite el acceso al realm. Se describe el origen del iframe por sus atributos: un
   * iframe vacío o srcdoc (creado al vuelo) es el patrón típico de evasión.
   */
  private ReportAccess(frame: unknown, access: RealmAccessData["Access"]): void {
    const element = frame as Element;
    const src = element.getAttribute("src");
    const source = element.hasAttribute("srcdoc")
      ? "srcdoc"
      : src === null || src === "" || src === "about:blank"
        ? "about:blank"
        : DescribeUrl(src, this.Context.GetBaseUrl()).Url;
    this.Context.Emit("runtime.realm", this.Name, { Frame: source, Access: access });
  }
}
