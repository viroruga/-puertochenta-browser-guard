/**
 * Comprobaciones de automatización y de consistencia del entorno.
 *
 * Retornan solo NOMBRES de señal. Los valores leídos (user agent, renderer WebGL,
 * idiomas, ...) se usan para comparar y se descartan: nunca se almacenan ni envían,
 * por lo que no se construye una huella identificable del usuario.
 */

type BrowserWindow = Window & typeof globalThis;

/** Globales que exponen herramientas de automatización conocidas. */
const ArtifactGlobals: readonly (readonly [string, string])[] = [
  ["__playwright__binding__", "playwright"],
  ["__pwInitScripts", "playwright"],
  ["_phantom", "phantomjs"],
  ["callPhantom", "phantomjs"],
  ["__nightmare", "nightmare"],
  ["domAutomation", "chromedriver"],
  ["domAutomationController", "chromedriver"],
  ["_selenium", "selenium"],
  ["callSelenium", "selenium"],
  ["_Selenium_IDE_Recorder", "selenium"],
  ["__webdriver_evaluate", "webdriver"],
  ["__driver_evaluate", "webdriver"],
  ["__webdriver_script_fn", "webdriver"],
  ["__fxdriver_unwrapped", "webdriver"],
  ["__selenium_unwrapped", "selenium"],
  ["Cypress", "cypress"],
];

/** Propiedades que inyecta chromedriver en window/document ("cdc_..." o "$cdc_..."). */
const ChromedriverKeyPattern = /^\$?[a-z]{3}_[a-zA-Z0-9]{22}_$|^\$?cdc_/;

/** Atributos que algunas herramientas agregan a <html>. */
const ArtifactAttributes: readonly string[] = ["webdriver", "selenium", "driver"];

/** Renderers WebGL por software, típicos de navegadores headless en servidores. */
const SoftwareRendererPattern = /swiftshader|llvmpipe|softpipe|mesa offscreen/i;

/** Marcas de User-Agent Client Hints (API no presente en todos los navegadores). */
function ReadBrands(navigator: Navigator | undefined): { brand: string }[] {
  const data = (navigator as { userAgentData?: { brands?: unknown } } | undefined)?.userAgentData;
  return Array.isArray(data?.brands) ? (data.brands as { brand: string }[]) : [];
}

function SafeKeys(target: object): string[] {
  try {
    return Object.keys(target);
  } catch {
    return [];
  }
}

/**
 * Señales de automatización: webdriver, headless y rastros de herramientas.
 */
export function DetectAutomationSignals(window: BrowserWindow): string[] {
  const signals = new Set<string>();
  const navigator = window.navigator as Navigator | undefined;

  if (navigator?.webdriver === true) {
    signals.add("webdriver");
  }

  const userAgent = navigator?.userAgent ?? "";
  const brands = ReadBrands(navigator);
  if (
    /HeadlessChrome|PhantomJS/i.test(userAgent) ||
    brands.some((b) => /Headless/i.test(b.brand))
  ) {
    signals.add("headless");
  }

  const record = window as unknown as Record<string, unknown>;
  for (const [key, tool] of ArtifactGlobals) {
    if (key in record) {
      signals.add(`artifact:${tool}`);
    }
  }

  const document = window.document as Document | undefined;
  const keys = [...SafeKeys(window), ...(document ? SafeKeys(document) : [])];
  if (keys.some((key) => ChromedriverKeyPattern.test(key))) {
    signals.add("artifact:chromedriver");
  }

  const root = document?.documentElement;
  if (root && ArtifactAttributes.some((attribute) => root.hasAttribute(attribute))) {
    signals.add("artifact:webdriver-attribute");
  }

  return [...signals];
}

/**
 * Obtiene el renderer WebGL y libera el contexto inmediatamente.
 * Solo se usa para compararlo contra renderers por software.
 */
function ReadWebGlRenderer(document: Document): string | null {
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl");
    if (!gl) {
      return null;
    }
    const debug = gl.getExtension("WEBGL_debug_renderer_info");
    const renderer: unknown = debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : null;
    gl.getExtension("WEBGL_lose_context")?.loseContext();
    return typeof renderer === "string" ? renderer : null;
  } catch {
    return null;
  }
}

/**
 * Señales de inconsistencia del entorno.
 *
 * Rendimiento: crear un contexto WebGL cuesta algunos milisegundos; se hace una
 * única vez por sesión y el contexto se libera de inmediato.
 */
export function DetectEnvironmentSignals(window: BrowserWindow): string[] {
  const signals: string[] = [];
  const navigator = window.navigator as Navigator | undefined;
  if (!navigator) {
    return signals;
  }
  const userAgent = navigator.userAgent;
  const isChromium = /Chrome\//.test(userAgent) && !/Edg\/|OPR\//.test(userAgent);
  const isMobile = /Mobi|Android/i.test(userAgent);

  if (Array.isArray(navigator.languages) && navigator.languages.length === 0) {
    signals.push("env-no-languages");
  }

  if (window.outerWidth === 0 && window.outerHeight === 0) {
    signals.push("env-zero-window");
  }

  const platform = navigator.platform;
  const claimsWindows = /Windows/.test(userAgent);
  const claimsMac = /Macintosh/.test(userAgent);
  if ((claimsWindows && /^Linux/.test(platform)) || (claimsMac && /^(Linux|Win)/.test(platform))) {
    signals.push("env-ua-mismatch");
  } else if (
    isChromium &&
    !isMobile &&
    typeof (window as { chrome?: unknown }).chrome === "undefined"
  ) {
    signals.push("env-ua-mismatch");
  }

  // navigator.plugins está obsoleto, pero Chrome de escritorio aún expone sus visores PDF.
  const plugins = (navigator as { plugins?: { length: number } }).plugins;
  if (isChromium && !isMobile && plugins?.length === 0) {
    signals.push("env-no-plugins");
  }

  const renderer = ReadWebGlRenderer(window.document);
  if (renderer !== null && SoftwareRendererPattern.test(renderer)) {
    signals.push("env-software-gl");
  }

  return signals;
}
