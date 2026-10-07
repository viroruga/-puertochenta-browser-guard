import { CallerStackFrom, RaiseStackTraceLimit, RestoreStackTraceLimit } from "../Utils/StackTrace";
import type { GuardContext } from "./GuardContext";

/**
 * Hooks de la interceptación. Los "Before" solo observan. TransformArgs puede
 * retornar argumentos nuevos (o null para no cambiar nada); se usa únicamente para
 * agregar el header de veredicto anti-scraping, que es opt-in. Si TransformArgs
 * falla, la llamada continúa con los argumentos originales.
 *
 * Inspect es un prefiltro de BeforeApply: si retorna null, la llamada continúa sin
 * ejecutar el hook ni capturar el stack. Sirve para observar APIs muy frecuentes
 * (p. ej. innerHTML) con costo mínimo; su resultado llega al hook como `inspection`.
 *
 * Con CaptureStack, los hooks "Before" reciben el stack de quien invocó la función
 * interceptada (sin frames de BrowserGuard). Tiene costo: solo para hooks que lo usan.
 */
export interface PatchHooks<T = undefined> {
  CaptureStack?: boolean;
  Inspect?: (thisArg: unknown, args: readonly unknown[]) => T | null;
  BeforeApply?: (
    thisArg: unknown,
    args: readonly unknown[],
    stack: string | undefined,
    inspection: T,
  ) => void;
  TransformArgs?: (thisArg: unknown, args: readonly unknown[]) => unknown[] | null;
  /**
   * Se ejecuta después de la llamada original, con su resultado (que no puede cambiar).
   * Si la llamada original lanza, no se ejecuta.
   */
  AfterApply?: (thisArg: unknown, result: unknown) => void;
  BeforeConstruct?: (args: readonly unknown[], stack: string | undefined) => void;
}

/**
 * Qué parte de la propiedad se intercepta:
 * - value: el valor (función o constructor), p. ej. window.fetch;
 * - setter: el setter de una propiedad accessor, p. ej. Element.prototype.innerHTML;
 * - getter: el getter de una propiedad accessor, p. ej. HTMLIFrameElement.prototype.contentWindow.
 */
export type PatchPart = "value" | "setter" | "getter";

/**
 * Estado mutable compartido con el proxy. Al restaurar se vacía, de modo que un
 * proxy que quede en una cadena ajena no retenga hooks ni contexto.
 */
interface PatchState<T> {
  Hooks: PatchHooks<T> | null;
  Context: GuardContext | null;
}

/**
 * Interceptación reversible de una función, constructor o setter mediante Proxy.
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
export class FunctionPatch<T = undefined> {
  private OriginalDescriptor: PropertyDescriptor | null = null;
  private OriginalValue: unknown = null;
  private ProxyRef: object | null = null;
  private State: PatchState<T> = { Hooks: null, Context: null };

  public constructor(
    private readonly Owner: object,
    private readonly Key: PropertyKey,
    private readonly Hooks: PatchHooks<T>,
    private readonly Context: GuardContext,
    private readonly Part: PatchPart = "value",
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
    const target = this.ResolveTarget(descriptor);
    if (typeof target !== "function") {
      return false;
    }

    const state: PatchState<T> = { Hooks: this.Hooks, Context: this.Context };

    const proxy: object = new Proxy(target as (...args: unknown[]) => unknown, {
      apply(original, thisArg: unknown, args: unknown[]): unknown {
        const hooks = state.Hooks;
        const context = state.Context;
        const hook = hooks?.BeforeApply;
        if (hook && context) {
          let inspection: T | null = undefined as T;
          if (hooks.Inspect) {
            try {
              inspection = hooks.Inspect(thisArg, args);
            } catch (error) {
              context.ReportInternalError(error);
              inspection = null;
            }
          }
          if (inspection !== null) {
            // El Error se crea aquí, no en un helper: su primer frame es esta trampa y el
            // siguiente es quien llamó (ver StackTrace). No mover a otra función.
            const frames = context.Config.Stack.MaxFrames;
            const limit = hooks.CaptureStack ? RaiseStackTraceLimit(frames + 1) : undefined;
            const origin = hooks.CaptureStack ? new Error() : null;
            RestoreStackTraceLimit(limit);
            const inspected = inspection;
            context.Safely(() => {
              hook(thisArg, args, origin ? CallerStackFrom(origin, frames) : undefined, inspected);
            });
          }
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
        const result: unknown = Reflect.apply(original, thisArg, finalArgs);
        const after = state.Hooks?.AfterApply;
        if (after) {
          state.Context?.Safely(() => {
            after(thisArg, result);
          });
        }
        return result;
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
      this.Install(descriptor, proxy);
    } catch {
      return false;
    }
    if (this.ReadInstalled() !== proxy) {
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
    try {
      if (this.ReadInstalled() === this.ProxyRef) {
        if (this.Part === "value" && IsAccessor(descriptor)) {
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

  /**
   * Función a interceptar según la parte elegida, o undefined si no es interceptable.
   * - value: propiedad de datos (caso habitual) o accessor con setter (algunos
   *   polyfills y entornos como jsdom exponen globales así).
   * - setter: el setter de una propiedad accessor configurable.
   */
  private ResolveTarget(descriptor: PropertyDescriptor): unknown {
    if (this.Part !== "value") {
      // Setter/getter se envuelven con un Proxy y se invocan con Reflect.apply (con su `this`).
      /* eslint-disable @typescript-eslint/unbound-method */
      const accessor = this.Part === "setter" ? descriptor.set : descriptor.get;
      /* eslint-enable @typescript-eslint/unbound-method */
      return descriptor.configurable === true ? accessor : undefined;
    }
    if (IsAccessor(descriptor)) {
      return descriptor.set === undefined ? undefined : Reflect.get(this.Owner, this.Key);
    }
    return descriptor.writable === true || descriptor.configurable === true
      ? descriptor.value
      : undefined;
  }

  private Install(descriptor: PropertyDescriptor, proxy: object): void {
    if (this.Part === "setter") {
      Object.defineProperty(this.Owner, this.Key, {
        ...descriptor,
        set: proxy as (value: unknown) => void,
      });
    } else if (this.Part === "getter") {
      Object.defineProperty(this.Owner, this.Key, { ...descriptor, get: proxy as () => unknown });
    } else if (IsAccessor(descriptor)) {
      Reflect.set(this.Owner, this.Key, proxy);
    } else {
      Object.defineProperty(this.Owner, this.Key, { ...descriptor, value: proxy });
    }
  }

  /** Valor instalado actualmente en la parte interceptada (para verificar y restaurar). */
  private ReadInstalled(): unknown {
    if (this.Part === "value") {
      return Reflect.get(this.Owner, this.Key);
    }
    // Solo se compara por identidad con el proxy instalado.
    const descriptor = Object.getOwnPropertyDescriptor(this.Owner, this.Key);
    /* eslint-disable @typescript-eslint/unbound-method */
    return this.Part === "setter" ? descriptor?.set : descriptor?.get;
    /* eslint-enable @typescript-eslint/unbound-method */
  }
}

function IsAccessor(descriptor: PropertyDescriptor): boolean {
  return descriptor.get !== undefined || descriptor.set !== undefined;
}
