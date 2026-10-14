/**
 * Buffer circular de capacidad fija. Al llenarse descarta los elementos más antiguos,
 * garantizando que la memoria utilizada nunca crezca sin límite.
 *
 * Lo usan la línea de tiempo forense (BrowserGuard) y el historial de hallazgos
 * (FindingHistory).
 */
export class RingBuffer<T> {
  private readonly Items: (T | undefined)[];
  /** Índice del elemento más antiguo. */
  private Head = 0;
  /** Elementos almacenados (≤ Capacity). */
  private Count = 0;

  public constructor(public readonly Capacity: number) {
    if (!Number.isInteger(Capacity) || Capacity <= 0) {
      throw new RangeError("RingBuffer capacity must be a positive integer");
    }
    this.Items = new Array<T | undefined>(Capacity);
  }

  /** Agrega un elemento; si el buffer está lleno, sobrescribe el más antiguo. */
  public Push(item: T): void {
    const index = (this.Head + this.Count) % this.Capacity;
    this.Items[index] = item;
    if (this.Count < this.Capacity) {
      this.Count++;
    } else {
      this.Head = (this.Head + 1) % this.Capacity;
    }
  }

  /**
   * Retorna una copia de los elementos en orden cronológico. Los valores `undefined`
   * se omiten (se usan internamente como hueco).
   */
  public ToArray(): T[] {
    const result: T[] = [];
    for (let i = 0; i < this.Count; i++) {
      const item = this.Items[(this.Head + i) % this.Capacity];
      if (item !== undefined) {
        result.push(item);
      }
    }
    return result;
  }

  public get Size(): number {
    return this.Count;
  }

  /** Vacía el buffer y suelta las referencias para que el GC pueda liberarlas. */
  public Clear(): void {
    this.Items.fill(undefined);
    this.Head = 0;
    this.Count = 0;
  }
}
