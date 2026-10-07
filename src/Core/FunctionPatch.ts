import { CallerStackFrom, RaiseStackTraceLimit, RestoreStackTraceLimit } from "../Utils/StackTrace";
import type { GuardContext } from "./GuardContext";

/**
 * Hooks de la interceptación. Los "Before" solo observan. TransformArgs puede
 * retornar argumentos nuevos (o null para no cambiar nada); se usa únicamente para
 * agregar el header de veredicto anti-scraping, que es opt-in. Si TransformArgs
 * falla, la llamada continúa con los argumentos originales.
 *
 * Con CaptureStack, los hooks "Before" reciben el stack de quien invocó la función
 * interceptada (sin frames de BrowserGuard). Tiene costo: solo para hooks que lo usan.
 */
export interface PatchHooks {
  CaptureStack?: boolean;
  BeforeApply?: (thisArg: unknown, args: readonly unknown[], stack: string | undefined) => void;
  TransformArgs?: (thisArg: unknown, args: readonly unknown[]) => unknown[] | null;
  BeforeConstruct?: (args: readonly unknown[], stack: string | undefined) => void;
}

/**
 * Estado mutable compartido con el proxy. Al restaurar se vacía, de modo que un
 * proxy que quede en una cadena ajena no retenga hooks ni contexto.
 */
interface PatchState {
  Hooks: PatchHooks | null;
  Context: GuardContext | null;
}

/**
 * Interceptación reversible de una función o constructor mediante Proxy.
 *
 * Por qué Proxy en lugar de una función envoltorio:
 * - preserva `name`, `length`, `prototype`, propiedades estáticas e `instanceof`;
 * - preserva `this`, argumentos, valor de retorno (incluida la Promise) y errores,
 *   porque delega con Reflect.apply / Reflect.construct;
 * - un error dentro de un hook nunca alcanza a la aplicación.
 *
 * Restauración segura: si al detener la propiedad sigue apuntando a nuestro proxy,
 * se restaura el descriptor original. Si otra librería la envolvió después,
 * restaurar rompería su cadena; en ese caso el proxy queda inerte (passthrough).
 */
export class FunctionPatch {
  private OriginalDescriptor: PropertyDescriptor | null = null;
  private OriginalValue: unknown = null;
  private ProxyRef: object | null = null;
  private State: PatchState = { Hooks: null, Context: null };

  public constructor(
    private readonly Owner: object,
    private readonly Key: PropertyKey,
    private readonly Hooks: PatchHooks,
    private readonly Context: GuardContext,
  ) {}

  /**
   * Instala la interceptación. Retorna false si la propiedad no es interceptable.
   */
  public Apply(): boolean {
    if (this.ProxyRef !== null) {
      return true;
    }
    const descriptor = Object.getOwnPropertyDescriptor(this.Owner, this.Key);
    if (!descriptor) {
      return false;
    }
    // Propiedad de datos (caso habitual en navegadores) o accessor con setter
    // (algunos polyfills y entornos como jsdom exponen globales así).
    const isAccessor = descriptor.get !== undefined || descriptor.set !== undefined;
    if (
      isAccessor ? descriptor.set === undefined : !descriptor.writable && !descriptor.configurable
    ) {
      return false;
    }
    const target: unknown = isAccessor ? Reflect.get(this.Owner, this.Key) : descriptor.value;
    if (typeof target !== "function") {
      return false;
    }

    const state: PatchState = { Hooks: this.Hooks, Context: this.Context };

    const proxy: object = new Proxy(target as (...args: unknown[]) => unknown, {
      apply(original, thisArg: unknown, args: unknown[]): unknown {
        const hooks = state.Hooks;
        const context = state.Context;
        const hook = hooks?.BeforeApply;
        if (hook && context) {
          // El Error se crea aquí, no en un helper: su primer frame es esta trampa y el
          // siguiente es quien llamó (ver StackTrace). No mover a otra función.
          const frames = context.Config.Stack.MaxFrames;
          const limit = hooks.CaptureStack ? RaiseStackTraceLimit(frames + 1) : undefined;
          const origin = hooks.CaptureStack ? new Error() : null;
          RestoreStackTraceLimit(limit);
          context.Safely(() => {
            hook(thisArg, args, origin ? CallerStackFrom(origin, frames) : undefined);
          });
        }
        let finalArgs = args;
        const transform = state.Hooks?.TransformArgs;
        if (transform) {
          try {
            finalArgs = transform(thisArg, args) ?? args;
          } catch (error) {
            state.Context?.ReportInternalError(error);
          }
        }
        return Reflect.apply(original, thisArg, finalArgs);
      },
      construct(original, args: unknown[], newTarget: (...args: unknown[]) => unknown): object {
        const hooks = state.Hooks;
        const context = state.Context;
        const hook = hooks?.BeforeConstruct;
        if (hook && context) {
          // Igual que en apply: el Error debe crearse en esta trampa.
          const frames = context.Config.Stack.MaxFrames;
          const limit = hooks.CaptureStack ? RaiseStackTraceLimit(frames + 1) : undefined;
          const origin = hooks.CaptureStack ? new Error() : null;
          RestoreStackTraceLimit(limit);
          context.Safely(() => {
            hook(args, origin ? CallerStackFrom(origin, frames) : undefined);
          });
        }
        // Si se construye directamente sobre el proxy se usa el constructor original
        // como newTarget; las subclases conservan su propio newTarget.
        return Reflect.construct(
          original,
          args,
          newTarget === proxy ? original : newTarget,
        ) as object;
      },
    });

    try {
      if (isAccessor) {
        Reflect.set(this.Owner, this.Key, proxy);
      } else {
        Object.defineProperty(this.Owner, this.Key, { ...descriptor, value: proxy });
      }
    } catch {
      return false;
    }
    if (Reflect.get(this.Owner, this.Key) !== proxy) {
      return false;
    }

    this.OriginalDescriptor = descriptor;
    this.OriginalValue = target;
    this.ProxyRef = proxy;
    this.State = state;
    this.Context.RegisterOwnFunction(proxy);
    return true;
  }

  /**
   * Deshace la interceptación dejando el entorno en su estado lógico original.
   */
  public Restore(): void {
    if (this.ProxyRef === null || this.OriginalDescriptor === null) {
      return;
    }
    // Desactivar primero: libera hooks y contexto aunque el proxy siga referenciado.
    this.State.Hooks = null;
    this.State.Context = null;

    const descriptor = this.OriginalDescriptor;
    const isAccessor = descriptor.get !== undefined || descriptor.set !== undefined;
    try {
      if (Reflect.get(this.Owner, this.Key) === this.ProxyRef) {
        if (isAccessor) {
          Reflect.set(this.Owner, this.Key, this.OriginalValue);
        } else {
          Object.defineProperty(this.Owner, this.Key, descriptor);
        }
      }
    } catch (error) {
      this.Context.ReportInternalError(error);
    }

    this.ProxyRef = null;
    this.OriginalDescriptor = null;
    this.OriginalValue = null;
  }

  public IsApplied(): boolean {
    return this.ProxyRef !== null;
  }
}
