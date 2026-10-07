/** Ventana para medir ráfagas. */
export const BurstWindowMs = 60_000;

/** Plantillas de URL recordadas para detectar barridos (memoria acotada). */
const MaxTrackedTemplates = 100;

interface SequenceState {
  Last: number;
  Run: number;
}

export interface RequestPattern {
  RequestsLastMinute: number;
  Burst: boolean;
  /** Plantilla de la URL con el id variable reemplazado, p. ej. "/product/{n}". */
  Template: string | null;
  /** Solicitudes consecutivas con id incremental (o decremental) en esa plantilla. */
  SequentialRun: number;
}

/**
 * Analiza el ritmo de solicitudes: ráfagas por minuto y barridos secuenciales de
 * ids en la ruta (/product/1, /product/2, ...). Memoria acotada.
 *
 * Limitación: las URLs llegan sin query string (se descarta por privacidad), por lo
 * que la paginación por query (?page=2) no se detecta como barrido.
 */
export class RequestPatternTracker {
  private Timestamps: number[] = [];
  private readonly Sequences = new Map<string, SequenceState>();

  public constructor(private readonly MaxPerMinute: number) {}

  public Record(url: string, now: number): RequestPattern {
    this.Timestamps.push(now);
    const cutoff = now - BurstWindowMs;
    if (this.Timestamps.length > this.MaxPerMinute + 1 || (this.Timestamps[0] ?? now) < cutoff) {
      this.Timestamps = this.Timestamps.filter((timestamp) => timestamp >= cutoff);
    }
    const count = this.Timestamps.length;
    const sequence = this.TrackSequence(url);
    return {
      RequestsLastMinute: count,
      Burst: count > this.MaxPerMinute,
      Template: sequence?.Template ?? null,
      SequentialRun: sequence?.Run ?? 0,
    };
  }

  private TrackSequence(url: string): { Template: string; Run: number } | null {
    const match = /^(.*\/)(\d{1,12})(\/[^/]*)?$/.exec(url);
    if (!match) {
      return null;
    }
    const template = `${match[1] ?? ""}{n}${match[3] ?? ""}`;
    const id = Number(match[2]);
    const state = this.Sequences.get(template);
    const run = state && Math.abs(id - state.Last) === 1 ? state.Run + 1 : 1;

    // Reinsertar mantiene el orden por uso reciente para descartar las más antiguas.
    this.Sequences.delete(template);
    this.Sequences.set(template, { Last: id, Run: run });
    if (this.Sequences.size > MaxTrackedTemplates) {
      const oldest = this.Sequences.keys().next().value;
      if (oldest !== undefined) {
        this.Sequences.delete(oldest);
      }
    }
    return { Template: template, Run: run };
  }
}
