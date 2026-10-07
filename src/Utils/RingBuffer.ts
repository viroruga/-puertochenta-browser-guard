/**
 * Buffer circular de capacidad fija. Al llenarse descarta los elementos más antiguos,
 * garantizando que la memoria utilizada nunca crezca sin límite.
 */
export class RingBuffer<T> {
  private readonly Items: (T | undefined)[];
  private Head = 0;
  private Count = 0;

  public constructor(public readonly Capacity: number) {
    if (!Number.isInteger(Capacity) || Capacity <= 0) {
      throw new RangeError("RingBuffer capacity must be a positive integer");
    }
    this.Items = new Array<T | undefined>(Capacity);
  }

  public Push(item: T): void {
    const index = (this.Head + this.Count) % this.Capacity;
    this.Items[index] = item;
    if (this.Count < this.Capacity) {
      this.Count++;
    } else {
      this.Head = (this.Head + 1) % this.Capacity;
    }
  }

  /** Retorna una copia de los elementos en orden cronológico. */
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

  public Clear(): void {
    this.Items.fill(undefined);
    this.Head = 0;
    this.Count = 0;
  }
}
