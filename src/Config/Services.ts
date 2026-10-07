/**
 * Servicios de terceros conocidos. Declararlos en `Services` agrega sus orígenes a las
 * listas permitidas y, en algunos casos, reconoce los wrappers que instalan sobre
 * funciones del runtime (p. ej. Sentry sobre fetch y setTimeout).
 */
export type KnownService =
  | "stripe"
  | "paypal"
  | "google-analytics"
  | "google-tag-manager"
  | "google-fonts"
  | "recaptcha"
  | "cloudflare-turnstile"
  | "youtube"
  | "sentry"
  | "hotjar"
  | "intercom"
  | "zone.js";

export interface ServiceDefinition {
  /** Orígenes desde los que el servicio carga scripts. */
  Scripts: readonly string[];
  /** Orígenes a los que el servicio envía solicitudes, carga recursos o embebe iframes. */
  Network: readonly string[];
  /**
   * Propiedades con las que el servicio marca sus wrappers apuntando a la función
   * original. Solo se confía en ellas si el servicio está declarado.
   */
  WrapperMarkers: readonly string[];
}

/**
 * Catálogo de orígenes según la documentación de CSP de cada proveedor. Es un punto de
 * partida: si un proveedor cambia sus dominios, el modo aprendizaje los muestra.
 */
export const ServiceCatalog: Readonly<Record<KnownService, ServiceDefinition>> = {
  stripe: {
    Scripts: ["https://js.stripe.com"],
    Network: ["https://*.stripe.com", "https://m.stripe.network"],
    WrapperMarkers: [],
  },
  paypal: {
    Scripts: ["https://www.paypal.com", "https://www.paypalobjects.com"],
    Network: ["https://*.paypal.com", "https://*.paypalobjects.com"],
    WrapperMarkers: [],
  },
  "google-analytics": {
    Scripts: ["https://www.googletagmanager.com", "https://www.google-analytics.com"],
    Network: [
      "https://*.google-analytics.com",
      "https://*.analytics.google.com",
      "https://www.googletagmanager.com",
      "https://stats.g.doubleclick.net",
    ],
    WrapperMarkers: [],
  },
  "google-tag-manager": {
    Scripts: ["https://www.googletagmanager.com"],
    Network: ["https://www.googletagmanager.com"],
    WrapperMarkers: [],
  },
  "google-fonts": {
    Scripts: [],
    Network: ["https://fonts.googleapis.com", "https://fonts.gstatic.com"],
    WrapperMarkers: [],
  },
  recaptcha: {
    Scripts: ["https://www.google.com", "https://www.gstatic.com", "https://www.recaptcha.net"],
    Network: ["https://www.google.com", "https://www.gstatic.com", "https://www.recaptcha.net"],
    WrapperMarkers: [],
  },
  "cloudflare-turnstile": {
    Scripts: ["https://challenges.cloudflare.com"],
    Network: ["https://challenges.cloudflare.com"],
    WrapperMarkers: [],
  },
  youtube: {
    Scripts: ["https://www.youtube.com"],
    Network: [
      "https://www.youtube.com",
      "https://www.youtube-nocookie.com",
      "https://*.ytimg.com",
      "https://*.googlevideo.com",
    ],
    WrapperMarkers: [],
  },
  sentry: {
    Scripts: ["https://browser.sentry-cdn.com", "https://js.sentry-cdn.com"],
    Network: [
      "https://*.ingest.sentry.io",
      "https://*.ingest.us.sentry.io",
      "https://*.ingest.de.sentry.io",
    ],
    WrapperMarkers: ["__sentry_original__"],
  },
  hotjar: {
    Scripts: ["https://static.hotjar.com", "https://script.hotjar.com"],
    Network: ["https://*.hotjar.com", "https://*.hotjar.io"],
    WrapperMarkers: [],
  },
  intercom: {
    Scripts: ["https://widget.intercom.io", "https://js.intercomcdn.com"],
    Network: ["https://*.intercom.io", "https://*.intercomcdn.com"],
    WrapperMarkers: [],
  },
  // Zone.js (Angular) envuelve setTimeout, fetch, XHR... y marca el original.
  "zone.js": {
    Scripts: [],
    Network: [],
    WrapperMarkers: ["__zone_symbol__OriginalDelegate"],
  },
};

export const KnownServices = Object.keys(ServiceCatalog) as KnownService[];

/**
 * Filtra nombres desconocidos o repetidos (tolerante a entradas inválidas).
 */
export function ResolveServices(value: unknown): KnownService[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const names = value.filter(
    (name): name is KnownService =>
      typeof name === "string" && Object.prototype.hasOwnProperty.call(ServiceCatalog, name),
  );
  return [...new Set(names)];
}

/** Une listas de orígenes sin duplicados, conservando el orden. */
export function MergeOrigins(base: readonly string[], extra: readonly string[]): string[] {
  return [...new Set([...base, ...extra])];
}

/**
 * Contribución combinada de los servicios declarados.
 */
export function ExpandServices(services: readonly KnownService[]): {
  Scripts: string[];
  Network: string[];
  WrapperMarkers: string[];
} {
  let scripts: string[] = [];
  let network: string[] = [];
  let markers: string[] = [];
  for (const name of services) {
    const service = ServiceCatalog[name];
    scripts = MergeOrigins(scripts, service.Scripts);
    network = MergeOrigins(network, service.Network);
    markers = MergeOrigins(markers, service.WrapperMarkers);
  }
  return { Scripts: scripts, Network: network, WrapperMarkers: markers };
}
