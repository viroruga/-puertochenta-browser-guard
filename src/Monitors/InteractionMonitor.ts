import type { BotActivityData, BotActivityReason } from "../Types/SecurityEvent";
import { BaseMonitor } from "./BaseMonitor";

/** Momentos (ms desde el inicio) en los que se emite un resumen de actividad. */
export const ActivityCheckpointsMs: readonly number[] = [10_000, 30_000, 60_000];

/**
 * Eventos sintéticos a partir de los cuales se consideran señal de bot.
 * Algunas aplicaciones llaman a element.click() de forma legítima (pocas veces).
 */
export const SyntheticEventThreshold = 10;

type CounterKey = "Pointer" | "Keyboard" | "Scroll" | "Touch";

const ObservedEvents: readonly (readonly [string, CounterKey])[] = [
  ["pointermove", "Pointer"],
  ["pointerdown", "Pointer"],
  ["mousemove", "Pointer"],
  ["mousedown", "Pointer"],
  ["click", "Pointer"],
  ["keydown", "Keyboard"],
  ["wheel", "Scroll"],
  ["scroll", "Scroll"],
  ["touchstart", "Touch"],
];

/**
 * Cuenta la presencia de interacción humana.
 *
 * Privacidad: solo incrementa contadores por tipo de evento. Nunca registra qué
 * tecla se pulsó, coordenadas, elementos objetivo ni tiempos individuales.
 *
 * Rendimiento: listeners pasivos en fase de captura que solo suman un número.
 * Los resúmenes se emiten al primer evento humano, al alcanzar el umbral de eventos
 * sintéticos (isTrusted === false) y en tres checkpoints (10 s, 30 s, 60 s).
 */
export class InteractionMonitor extends BaseMonitor {
  public readonly Name = "InteractionMonitor";
  private readonly Counters: Record<CounterKey | "Untrusted", number> = {
    Pointer: 0,
    Keyboard: 0,
    Scroll: 0,
    Touch: 0,
    Untrusted: 0,
  };
  private StartedAt = 0;
  private ReportedHuman = false;
  private ReportedSynthetic = false;
  // Ids de window.setTimeout (number en el navegador), independientes de los tipos de Node.
  private Timers: number[] = [];
  private ClearTimer: ((id: number) => void) | null = null;
  private readonly Listeners = new Map<string, EventListener>();

  protected OnStart(): boolean {
    const window = this.Context.Window;
    this.StartedAt = Date.now();

    for (const [type, counter] of ObservedEvents) {
      const listener: EventListener = (event) => {
        this.OnInput(event, counter);
      };
      this.Listeners.set(type, listener);
      window.addEventListener(type, listener, { capture: true, passive: true });
    }

    // Referencias propias: un reemplazo posterior de setTimeout no afecta los checkpoints.
    const setTimer = window.setTimeout.bind(window);
    this.ClearTimer = window.clearTimeout.bind(window);
    this.Timers = ActivityCheckpointsMs.map((delay) =>
      setTimer(() => {
        this.Emit("checkpoint");
      }, delay),
    );
    return true;
  }

  protected OnStop(): void {
    const window = this.Context.Window;
    for (const [type, listener] of this.Listeners) {
      window.removeEventListener(type, listener, { capture: true });
    }
    this.Listeners.clear();
    for (const timer of this.Timers) {
      this.ClearTimer?.(timer);
    }
    this.Timers = [];
  }

  private OnInput(event: Event, counter: CounterKey): void {
    if (!event.isTrusted) {
      this.Counters.Untrusted++;
      if (!this.ReportedSynthetic && this.Counters.Untrusted >= SyntheticEventThreshold) {
        this.ReportedSynthetic = true;
        this.Emit("synthetic-threshold");
      }
      return;
    }
    this.Counters[counter]++;
    // "scroll" puede dispararse sin intervención humana (anclas, restauración).
    if (!this.ReportedHuman && counter !== "Scroll") {
      this.ReportedHuman = true;
      this.Emit("first-interaction");
    }
  }

  private Emit(reason: BotActivityReason): void {
    const data: BotActivityData = {
      Reason: reason,
      ElapsedMs: Date.now() - this.StartedAt,
      ...this.Counters,
      Visible: this.Context.Window.document.visibilityState !== "hidden",
    };
    this.Context.Emit("bot.activity", this.Name, data);
  }
}
