import type {
  MonitoredPrototype,
  PrototypeChangeData,
  PrototypeChangeKind,
} from "../Types/SecurityEvent";
import { AnalyzeFunction } from "../Utils/NativeFunctionUtils";
import { PeriodicTask } from "../Utils/PeriodicTask";
import { BaseMonitor } from "./BaseMonitor";

/**
 * Foto de un descriptor. Se guardan referencias (no copias) de valores y accessors:
 * ya están vivos en el prototipo, por lo que no generan retención adicional.
 */
interface DescriptorSnapshot {
  Value: unknown;
  Get: unknown;
  Set: unknown;
  Writable: boolean | undefined;
  Enumerable: boolean | undefined;
  Configurable: boolean | undefined;
}

/** Foto de un prototipo: clave propia (string o symbol) → descriptor. */
type PrototypeSnapshot = Map<PropertyKey, DescriptorSnapshot>;

/**
 * Límite de eventos por verificación: si un polyfill agrega decenas de métodos
 * de una vez, no se inunda el pipeline. Los cambios que exceden el límite no se
 * reportan: el baseline se actualiza igualmente.
 */
export const MaxChangesPerCheck = 50;

/**
 * Prototipos monitoreados. Se usan los intrínsecos del realm donde se ejecuta
 * la librería, que es el mismo que el de la aplicación (no los de Context.Window: este
 * monitor no se replica en los iframes).
 */
const Targets: readonly (readonly [MonitoredPrototype, object])[] = [
  ["Object.prototype", Object.prototype],
  ["Array.prototype", Array.prototype],
  ["Function.prototype", Function.prototype],
  ["String.prototype", String.prototype],
  ["Promise.prototype", Promise.prototype],
];

/** Toma la foto de las propiedades propias (incluidas symbols y no enumerables). */
function TakeSnapshot(target: object): PrototypeSnapshot {
  const snapshot: PrototypeSnapshot = new Map();
  for (const key of Reflect.ownKeys(target)) {
    // getOwnPropertyDescriptor no invoca getters: es seguro frente a accessors hostiles.
    const descriptor = Object.getOwnPropertyDescriptor(target, key);
    if (descriptor) {
      /* eslint-disable @typescript-eslint/unbound-method -- Solo se comparan por identidad. */
      snapshot.set(key, {
        Value: descriptor.value,
        Get: descriptor.get,
        Set: descriptor.set,
        Writable: descriptor.writable,
        Enumerable: descriptor.enumerable,
        Configurable: descriptor.configurable,
      });
      /* eslint-enable @typescript-eslint/unbound-method */
    }
  }
  return snapshot;
}

/** Compara dos descriptores por identidad de valores y por sus atributos. */
function IsSameDescriptor(a: DescriptorSnapshot, b: DescriptorSnapshot): boolean {
  return (
    a.Value === b.Value &&
    a.Get === b.Get &&
    a.Set === b.Set &&
    a.Writable === b.Writable &&
    a.Enumerable === b.Enumerable &&
    a.Configurable === b.Configurable
  );
}

/** Tipo informado en el evento: "accessor" para getters/setters, si no `typeof` del valor. */
function DescribeValueType(snapshot: DescriptorSnapshot): string {
  return snapshot.Get !== undefined || snapshot.Set !== undefined
    ? "accessor"
    : typeof snapshot.Value;
}

/**
 * Detecta cambios en Object/Array/Function/String/Promise.prototype (prototype pollution,
 * sobrescritura de métodos nativos) y emite `prototype.changed`, que consume
 * PrototypePollutionDetector.
 *
 * Estrategia: no existe forma de observar prototipos nativos sin envolverlos
 * (lo cual alteraría el comportamiento), por lo que se toma un baseline al iniciar
 * y se compara periódicamente. La comparación es por referencia de descriptores
 * (~150 propiedades en total), se ejecuta en tiempo ocioso y con intervalo
 * configurable (por defecto 2-5 s según preset). Nunca se usa polling agresivo.
 *
 * Privacidad: el evento solo incluye el nombre de la propiedad y el tipo del valor; nunca
 * el valor en sí.
 */
export class PrototypeMonitor extends BaseMonitor {
  public readonly Name = "PrototypeMonitor";
  /** Estado al iniciar: volver a él es una reversión, no un cambio sospechoso. */
  private Initial = new Map<MonitoredPrototype, PrototypeSnapshot>();
  /** Último estado observado. */
  private Baseline = new Map<MonitoredPrototype, PrototypeSnapshot>();
  private Task: PeriodicTask | null = null;

  protected OnStart(): boolean {
    for (const [name, target] of Targets) {
      const snapshot = TakeSnapshot(target);
      this.Initial.set(name, snapshot);
      this.Baseline.set(name, snapshot);
    }
    this.Task = new PeriodicTask(() => {
      this.CheckNow();
    }, this.Context.Config.Integrity.IntervalMs);
    this.Task.Start();
    return true;
  }

  protected OnStop(): void {
    this.Task?.Stop();
    this.Task = null;
    this.Initial = new Map();
    this.Baseline = new Map();
  }

  /**
   * Compara el estado actual contra el baseline, emite los cambios y actualiza el baseline.
   * Cada cambio se reporta una única vez.
   */
  public CheckNow(): void {
    if (!this.IsRunning()) {
      return;
    }
    let emitted = 0;
    for (const [name, target] of Targets) {
      const previous = this.Baseline.get(name);
      // Defensivo: sin baseline (no debería ocurrir mientras corre) no hay contra qué comparar.
      if (!previous) {
        continue;
      }
      const current = TakeSnapshot(target);
      const initial = this.Initial.get(name) ?? new Map<PropertyKey, DescriptorSnapshot>();
      for (const change of this.Diff(name, previous, current, initial)) {
        // El límite es global a la verificación: al alcanzarlo, los prototipos restantes
        // tampoco emiten (pero su baseline se actualiza igual).
        if (emitted >= MaxChangesPerCheck) {
          break;
        }
        this.Context.Emit("prototype.changed", this.Name, change);
        emitted++;
      }
      // Se avanza el baseline: cada cambio se reporta una sola vez.
      this.Baseline.set(name, current);
    }
  }

  /**
   * Genera los cambios entre dos snapshots. Omite las propiedades que volvieron a su
   * estado inicial (p. ej. al eliminar una propiedad agregada después de Start).
   */
  private *Diff(
    name: MonitoredPrototype,
    previous: PrototypeSnapshot,
    current: PrototypeSnapshot,
    initial: PrototypeSnapshot,
  ): Generator<PrototypeChangeData> {
    // La propiedad está exactamente como al iniciar (incluida su ausencia).
    const isRevert = (key: PropertyKey): boolean => {
      const original = initial.get(key);
      const now = current.get(key);
      return original === undefined || now === undefined
        ? original === now
        : IsSameDescriptor(original, now);
    };

    for (const [key, snapshot] of current) {
      const before = previous.get(key);
      if (!before) {
        if (!isRevert(key)) {
          yield this.CreateChange(name, key, "added", snapshot);
        }
      } else if (!IsSameDescriptor(before, snapshot) && !isRevert(key)) {
        yield this.CreateChange(name, key, "modified", snapshot, before);
      }
    }
    for (const [key, snapshot] of previous) {
      if (!current.has(key) && !isRevert(key)) {
        yield this.CreateChange(name, key, "removed", undefined, snapshot);
      }
    }
  }

  /**
   * Construye el evento de un cambio. Para funciones se indica si parecen nativas antes y
   * después: sobrescribir un método nativo con código propio es la señal más relevante.
   */
  private CreateChange(
    target: MonitoredPrototype,
    key: PropertyKey,
    change: PrototypeChangeKind,
    snapshot?: DescriptorSnapshot,
    previous?: DescriptorSnapshot,
  ): PrototypeChangeData {
    // String() es seguro con symbols ("Symbol(desc)"), a diferencia de la concatenación.
    const property = String(key);
    const data: PrototypeChangeData = { Target: target, Property: property, Change: change };

    if (snapshot) {
      data.ValueType = DescribeValueType(snapshot);
      data.IsAccessor = data.ValueType === "accessor";
      if (typeof snapshot.Value === "function") {
        data.LooksNative = AnalyzeFunction(snapshot.Value, { ExpectedName: property }).LooksNative;
      }
    }
    if (previous) {
      data.PreviousValueType = DescribeValueType(previous);
      if (typeof previous.Value === "function") {
        data.PreviousLooksNative = AnalyzeFunction(previous.Value, {
          ExpectedName: property,
        }).LooksNative;
      }
    }
    return data;
  }
}
