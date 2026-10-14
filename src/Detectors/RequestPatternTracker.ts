/** Ventana deslizante para medir ráfagas (el límite se expresa por minuto). */
export const BurstWindowMs = 60_000;

/** Plantillas de URL recordadas para detectar barridos (memoria acotada). */
const MaxTrackedTemplates = 100;

/** Estado de un barrido por plantilla: último id visto y largo de la racha actual. */
interface SequenceState {
  Last: number;
  Run: number;
}

/** Resultado de registrar una solicitud: ritmo actual y barrido secuencial, si lo hay. */
export interface RequestPattern {
  /** Solicitudes registradas en los últimos BurstWindowMs (incluida la actual). */
  RequestsLastMinute: number;
  /** true si se superó MaxRequestsPerMinute dentro de la ventana. */
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
 *
 * Lo usa BotDetector, que decide qué solicitudes cuentan y deduplica las señales.
 */
export class RequestPatternTracker {
  /** Timestamps de las solicitudes recientes, en orden de llegada. */
  private Timestamps: number[] = [];
  /** Barridos en curso por plantilla; el orden de inserción equivale a uso reciente (LRU). */
  private readonly Sequences = new Map<string, SequenceState>();

  public constructor(private readonly MaxPerMinute: number) {}

  /**
   * Registra una solicitud (URL ya sanitizada, sin query) y retorna el patrón resultante.
   * `now` es el timestamp del evento, no el reloj actual, para que el análisis sea
   * determinista.
   */
  public Record(url: string, now: number): RequestPattern {
    this.Timestamps.push(now);
    const cutoff = now - BurstWindowMs;
    // Se filtra solo cuando puede haber entradas vencidas, para no recorrer el arreglo en
    // cada solicitud. Ojo: con timestamps crecientes, el filtro solo descarta lo que salió
    // de la ventana; durante una ráfaga sostenida el arreglo crece hasta la cantidad de
    // solicitudes del último minuto (no se recorta a MaxPerMinute + 1).
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

  /**
   * Detecta un id numérico en el último segmento de la ruta (o en el penúltimo, seguido
   * de un segmento final: /product/42/reviews) y cuenta cuántas solicitudes seguidas a la
   * misma plantilla difieren en exactamente 1. Un salto rompe la racha y la reinicia en 1.
   */
  private TrackSequence(url: string): { Template: string; Run: number } | null {
    // Hasta 12 dígitos: cubre ids habituales y evita confundir timestamps largos con ids.
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
