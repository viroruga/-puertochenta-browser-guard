import type { CspViolationData } from "../Types/SecurityEvent";
import { DescribeUrl } from "../Utils/UrlUtils";
import { BaseMonitor } from "./BaseMonitor";

/** Longitud máxima para valores no-URL de blockedURI ("inline", "eval", ...). */
const MaxKeywordLength = 64;

/**
 * Escucha el evento `securitypolicyviolation` y lo envía al EventBus como
 * `csp.violation`, que consume CspViolationDetector.
 *
 * No intercepta ninguna API: el navegador ya informa las violaciones; este monitor solo
 * las normaliza. Es la vía por la que se observan los usos de eval/new Function bloqueados
 * por CSP (SinkMonitor no los intercepta).
 *
 * El listener se registra en fase de captura sobre document para recibir el evento
 * aunque la aplicación detenga su propagación, y como pasivo para no afectar
 * el rendimiento.
 *
 * Privacidad: las URLs (bloqueada y archivo de origen) se sanean sin query ni fragmento.
 */
export class CspMonitor extends BaseMonitor {
  public readonly Name = "CspMonitor";
  /** Referencia estable: removeEventListener necesita la misma función que se registró. */
  private readonly Listener = (event: Event): void => {
    this.Context.Safely(() => {
      this.OnViolation(event);
    });
  };
  /** Documento donde se registró el listener, para retirarlo del mismo en OnStop. */
  private Target: Document | null = null;

  protected OnStart(): boolean {
    const document = this.Context.Window.document;
    document.addEventListener("securitypolicyviolation", this.Listener, {
      capture: true,
      passive: true,
    });
    this.Target = document;
    return true;
  }

  protected OnStop(): void {
    this.Target?.removeEventListener("securitypolicyviolation", this.Listener, { capture: true });
    this.Target = null;
  }

  /**
   * Sanea un valor que puede ser URL o palabra clave del navegador.
   *
   * blockedURI/sourceFile pueden contener una URL completa (con tokens en la query) o una
   * palabra clave como "inline", "eval" o "wasm-eval". Solo lo que tiene esquema se trata
   * como URL; el resto se trunca para acotar valores inesperados.
   */
  private DescribeLocation(value: string): { Value: string; Origin: string | null } {
    if (/^[a-z][a-z0-9+.-]*:/i.test(value)) {
      const described = DescribeUrl(value, this.Context.GetBaseUrl());
      return { Value: described.Url, Origin: described.Origin };
    }
    return { Value: value.slice(0, MaxKeywordLength), Origin: null };
  }

  /**
   * Normaliza la violación y la emite.
   *
   * Los campos se leen como opcionales: algunos navegadores antiguos (o eventos
   * sintéticos) no los incluyen todos.
   */
  private OnViolation(event: Partial<SecurityPolicyViolationEvent>): void {
    const blocked = this.DescribeLocation(event.blockedURI ?? "");
    const source = this.DescribeLocation(event.sourceFile ?? "");

    const data: CspViolationData = {
      BlockedUri: blocked.Value,
      BlockedOrigin: blocked.Origin,
      ViolatedDirective: event.violatedDirective ?? "",
      EffectiveDirective: event.effectiveDirective ?? "",
      SourceFile: source.Value,
      LineNumber: event.lineNumber ?? 0,
      ColumnNumber: event.columnNumber ?? 0,
      Disposition: event.disposition ?? "enforce",
    };
    this.Context.Emit("csp.violation", this.Name, data);
  }
}
