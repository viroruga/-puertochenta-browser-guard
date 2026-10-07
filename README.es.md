# @puertochenta/browser-guard

> [English](README.md) · **Español**

**Browser Runtime Security / Client-Side Intrusion Detection** para aplicaciones web.

BrowserGuard se ejecuta dentro del navegador, observa el runtime de tu aplicación y detecta
indicadores de comportamiento sospechoso: conexiones de red inesperadas, inyección dinámica de
scripts, violaciones CSP, prototype pollution y modificación de funciones nativas. Cada hallazgo
recibe un puntaje de riesgo (0-100) y una severidad, y se reporta localmente.

```ts
import { BrowserGuard } from "@puertochenta/browser-guard";

const Guard = BrowserGuard.Start({ Preset: "strict" });

Guard.On("Threat", (Finding) => {
  console.log(Finding);
});
```

- ESM, tipos TypeScript incluidos y tree shaking (`sideEffects: false`).
- Sin dependencias en runtime. Agnóstico de framework: React, Vue, Angular, Svelte o Vanilla JS.
- Las funciones opcionales se publican como plugins en rutas separadas: solo descargas lo que usas.
- Seguro de importar en SSR (Next.js, Nuxt): solo se activa en el navegador.

---

## Índice

- [Qué es BrowserGuard](#qué-es-browserguard)
- [Qué NO es BrowserGuard](#qué-no-es-browserguard)
- [Instalación](#instalación)
- [Quick start](#quick-start)
- [API](#api)
- [Configuración](#configuración)
- [Presets](#presets)
- [Monitores](#monitores)
- [Detección y puntaje de riesgo](#detección-y-puntaje-de-riesgo)
- [Eventos](#eventos)
- [Ejemplos](#ejemplos)
- [Plugins](#plugins)
- [Envío remoto](#envío-remoto)
- [Anti-scraping](#anti-scraping)
- [Limitaciones](#limitaciones)
- [Seguridad](#seguridad)
- [Performance](#performance)
- [Arquitectura](#arquitectura)
- [Desarrollo](#desarrollo)
- [Roadmap](#roadmap)

---

## Qué es BrowserGuard

Una capa de **observabilidad de seguridad del lado cliente**. Su modelo es estrictamente:

```text
observe → analyze → score → report
```

BrowserGuard:

- observa `fetch`, `XMLHttpRequest`, `WebSocket`, inserciones de `<script>`, `<iframe>`, `<object>`
  y `<embed>`, sinks de DOM XSS (`innerHTML`, `document.write`, ...), violaciones CSP, prototipos
  nativos y funciones críticas del runtime;
- analiza esos eventos con detectores especializados;
- asigna un puntaje de riesgo y una severidad (`info`, `low`, `medium`, `high`, `critical`);
- reporta a través de eventos a los que tu aplicación puede suscribirse
  (por ejemplo, para enviarlos a tu SIEM).

Es útil para detectar en producción comportamientos compatibles con XSS, skimming
(Magecart), dependencias comprometidas, extensiones maliciosas o exfiltración de datos, y para
auditar en desarrollo qué hace realmente tu aplicación.

## Qué NO es BrowserGuard

- **No detecta "cualquier ataque".** Detecta _indicadores_ de comportamiento sospechoso.
  Un atacante que ejecuta código antes que BrowserGuard, o que conoce su funcionamiento,
  puede evadirlo (ver [Limitaciones](#limitaciones)).
- **No bloquea solicitudes ni scripts.** Detecta y reporta. La única reacción activa es la
  protección de contenido opcional de [Anti-scraping](#anti-scraping).
- **No reemplaza** a CSP, Trusted Types, SRI, un WAF, un EDR, un SIEM ni la seguridad del backend.
  Es una capa complementaria de visibilidad. La mejor defensa sigue siendo una CSP estricta.
- **No es telemetría.** No envía datos a ningún servidor por defecto; el envío remoto solo se
  activa si configuras tu propio endpoint.

## Instalación

```bash
pnpm add @puertochenta/browser-guard
# o
npm install @puertochenta/browser-guard
# o
yarn add @puertochenta/browser-guard
```

Requiere un navegador moderno (ES2020, `Proxy`, `MutationObserver`).

## Quick start

> **Inicializa BrowserGuard lo antes posible.** Solo puede observar lo que ocurre _después_
> de `Start()`. Importa el módulo de arranque antes que cualquier otro código de la aplicación.

```ts
import { BrowserGuard } from "@puertochenta/browser-guard";

const Guard = BrowserGuard.Start({
  Preset: "strict",

  Network: {
    AllowedOrigins: [window.location.origin, "https://api.example.com"],
  },

  Dom: {
    AllowedScriptOrigins: [window.location.origin, "https://cdn.example.com"],
  },
});

Guard.On("Critical", (Finding) => {
  console.error(Finding);
});
```

## API

| Método                                                         | Descripción                                                                                                                                                                                                  |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `BrowserGuard.Start(config?)`                                  | Inicia todos los monitores habilitados y retorna la instancia activa. **Idempotente**: si ya hay una instancia en ejecución la retorna e ignora la nueva configuración. En SSR retorna una instancia inerte. |
| `BrowserGuard.Stop()` / `Guard.Stop()`                         | Detiene los monitores y restaura **todas** las funciones interceptadas, listeners, observers y timers.                                                                                                       |
| `BrowserGuard.On(event, handler)` / `Guard.On(...)`            | Suscribe un manejador. Retorna una función para desuscribirlo.                                                                                                                                               |
| `BrowserGuard.Off(event, handler)` / `Guard.Off(...)`          | Desuscribe un manejador.                                                                                                                                                                                     |
| `Guard.Once(event, handler)`                                   | Suscripción de una sola ejecución.                                                                                                                                                                           |
| `BrowserGuard.GetReport()` / `Guard.GetReport()`               | Historial de hallazgos y estadísticas.                                                                                                                                                                       |
| `BrowserGuard.GetStatus()` / `Guard.GetStatus()`               | Estado de ejecución, monitores activos, contadores internos.                                                                                                                                                 |
| `BrowserGuard.GetTimeline()` / `Guard.GetTimeline()`           | Línea de tiempo de eventos internos (solo en modo forense).                                                                                                                                                  |
| `BrowserGuard.GetInstance()`                                   | Instancia en ejecución o `null`.                                                                                                                                                                             |
| `Guard.GetConfig()`                                            | Copia de la configuración efectiva.                                                                                                                                                                          |
| `BrowserGuard.GetBotAssessment()` / `Guard.GetBotAssessment()` | Veredicto anti-scraping de la sesión (`null` si no está habilitado).                                                                                                                                         |

Los métodos estáticos operan sobre la instancia activa; sin instancia activa no hacen nada
(`GetReport()` y `GetStatus()` retornan `null`).

```ts
const Report = Guard.GetReport();
// {
//   StartedAt: 1760000000000,
//   Findings: SecurityFinding[],
//   Statistics: { Total, Critical, High, Medium, Low, Info }
// }
```

### SecurityFinding

```ts
interface SecurityFinding {
  Id: string;
  Timestamp: number;
  Category:
    | "network"
    | "script-injection"
    | "prototype-pollution"
    | "runtime-integrity"
    | "csp"
    | "dom"
    | "xss"
    | "bot";
  Severity: "info" | "low" | "medium" | "high" | "critical";
  Title: string;
  Description: string;
  RiskScore: number; // 0 - 100
  Signals: string[]; // señales que contribuyeron al puntaje
  EventId: string;
  Evidence?: unknown; // saneada: nunca contiene secretos
  Stack?: string; // limpio, sin frames internos de BrowserGuard
}
```

Los hallazgos están congelados (`Object.freeze`): los manejadores no pueden alterar el historial.

## Configuración

Todas las propiedades son opcionales. Los valores faltantes se completan con el preset
(por defecto `balanced`). Las entradas inválidas se ignoran sin lanzar excepciones.

```ts
interface BrowserGuardConfig {
  Preset?: "development" | "balanced" | "strict" | "forensic";

  // "notice": solo un aviso de monitoreo (por defecto, salvo en development)
  // "findings": cada hallazgo en detalle (por defecto en development)
  // "silent": nada. true = "findings", false = "silent"
  Console?: boolean | "silent" | "notice" | "findings";

  Notice?: {
    Title?: string; // por defecto: "Security monitoring active"
    Message?: string;
  };

  Monitors?: {
    Fetch?: boolean;
    Xhr?: boolean;
    WebSocket?: boolean;
    Dom?: boolean;
    Csp?: boolean;
    Prototype?: boolean;
    Runtime?: boolean; // integridad de funciones críticas
    Sinks?: boolean; // sinks de DOM XSS: innerHTML, document.write, setTimeout("..."), ...
  };

  Network?: {
    AllowedOrigins?: string[]; // "https://api.example.com" o "https://*.example.com"
    BlockedOrigins?: string[]; // se detectan y reportan como critical; no se bloquean
  };

  Dom?: {
    AllowedScriptOrigins?: string[]; // el origen propio siempre está permitido
  };

  Forensic?: {
    Enabled?: boolean;
    MaxEvents?: number; // tamaño del ring buffer (10 - 100000). Por defecto: 1000
  };

  History?: {
    MaxFindings?: number; // hallazgos retenidos (10 - 100000). Por defecto: 500
  };

  Integrity?: {
    IntervalMs?: number; // verificación de prototipos/runtime (500 - 600000)
  };

  Risk?: {
    MinSeverity?: Severity; // umbral para registrar y emitir hallazgos
    Weights?: Partial<Record<RiskSignal, number>>; // ver "Detección y puntaje de riesgo"
  };

  Reporters?: Reporter[]; // reporters propios (SIEM, analítica, ...)

  Plugins?: GuardPlugin[]; // funciones opcionales, ver "Plugins"
}
```

Valores por defecto seguros:

- todos los monitores habilitados;
- listas de orígenes vacías: todo origen externo se considera **desconocido**;
- sin modo forense; historial y línea de tiempo siempre acotados;
- los orígenes se normalizan (minúsculas, sin ruta) y se deduplican.

## Presets

| Preset        | Umbral de hallazgos | Consola                            | Intervalo de integridad | Línea de tiempo   | Uso                                                         |
| ------------- | ------------------- | ---------------------------------- | ----------------------- | ----------------- | ----------------------------------------------------------- |
| `development` | `info`              | `findings` desde `info`            | 2 s                     | no                | Mucho detalle: información, warnings y eventos sospechosos. |
| `balanced`    | `low`               | `notice`                           | 5 s                     | no                | **Recomendado** para uso general.                           |
| `strict`      | `medium`            | `notice`                           | 3 s                     | no                | Solo comportamientos relevantes o de riesgo elevado.        |
| `forensic`    | `info`              | `notice` (`findings` desde medium) | 2 s                     | sí (1000 eventos) | Cronología ampliada para análisis posterior.                |

`Risk.MinSeverity` sobrescribe el umbral de hallazgos y el de consola. La columna _Consola_
indica el modo por defecto; el umbral entre paréntesis aplica si eliges `Console: "findings"`.

## Monitores

Los monitores **solo observan y generan eventos**; nunca deciden si algo es un ataque.

| Monitor              | Observa                                                                                                                                                                                                                                      | Registra                                                                                                                                     |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `FetchMonitor`       | `window.fetch`                                                                                                                                                                                                                               | URL saneada, método, origen, timestamp, stack                                                                                                |
| `XhrMonitor`         | `XMLHttpRequest.prototype.open` / `send`                                                                                                                                                                                                     | método, URL saneada, origen, timestamp, stack (al enviar)                                                                                    |
| `WebSocketMonitor`   | `new WebSocket()`                                                                                                                                                                                                                            | URL saneada, origen, protocolos, stack. No inspecciona mensajes.                                                                             |
| `DomMonitor`         | `MutationObserver` (childList + subtree)                                                                                                                                                                                                     | `script`, `iframe`, `object`, `embed` insertados: `src`, `type`, `async`, `defer`, `integrity`, `crossOrigin`; para inline, solo la longitud |
| Sinks de DOM XSS     | Un prefiltro barato descarta las escrituras inofensivas sin análisis detallado, sin capturar stack y sin leer `location`. Costo medido por llamada inofensiva (Chrome / Firefox): `innerHTML` +0,5 / +0,7 µs, `setAttribute` +0,2 / +0,3 µs. |
| `CspMonitor`         | evento `securitypolicyviolation`                                                                                                                                                                                                             | `blockedURI`, `violatedDirective`, `effectiveDirective`, `sourceFile`, `lineNumber`, `columnNumber`, `disposition`                           |
| `PrototypeMonitor`   | `Object`, `Array`, `Function`, `String`, `Promise` `.prototype`                                                                                                                                                                              | propiedad nueva, eliminada o descriptor modificado                                                                                           |
| `RuntimeMonitor`     | `fetch`, `XHR.open/send`, `WebSocket`, `setTimeout`, `setInterval`, `eval`, `Function`, `Element.prototype.appendChild/setAttribute`, `Function.prototype.toString`                                                                          | reemplazo, eliminación o modificación previa al inicio                                                                                       |
| `SinkMonitor`        | setters de `innerHTML`/`outerHTML`, `insertAdjacentHTML`, `document.write`, `createContextualFragment`, `srcdoc`, `setAttribute`, `setTimeout`/`setInterval` con string                                                                      | sink, elemento, longitud y nombres de indicadores (nunca el contenido), stack                                                                |
| `AutomationMonitor`  | rastros de automatización y entorno (solo con `AntiScraping`)                                                                                                                                                                                | nombres de señal, nunca valores                                                                                                              |
| `InteractionMonitor` | mouse, teclado, scroll, touch (solo con `AntiScraping`)                                                                                                                                                                                      | contadores por tipo y eventos sintéticos; nunca teclas ni coordenadas                                                                        |

**Interceptación transparente.** `fetch`, `XHR` y `WebSocket` se interceptan con `Proxy`, que
preserva argumentos, `this`, la Promise, el valor de retorno, los errores, `name`, `length`,
propiedades estáticas, `instanceof` y las subclases. Un error interno de BrowserGuard nunca
llega a la aplicación.

**Restauración segura.** `Stop()` restaura el descriptor original exacto. Si otra librería
envolvió la función _después_ de BrowserGuard, restaurar rompería su cadena: en ese caso el
interceptor queda inerte (passthrough) y libera todas sus referencias.

**Reversiones.** Si una modificación vuelve al estado inicial (por ejemplo, se elimina una
propiedad agregada a un prototipo o se restaura `setTimeout`), no se reporta.

## Detección y puntaje de riesgo

Los detectores convierten eventos en hallazgos candidatos con **señales** con nombre.
`RiskEngine` suma los pesos de las señales, limita el resultado a 0-100 y lo traduce a severidad:

| Puntaje   | 0-19 | 20-39 | 40-59  | 60-79 | 80-100   |
| --------- | ---- | ----- | ------ | ----- | -------- |
| Severidad | info | low   | medium | high  | critical |

### NetworkDetector

| Destino                                              | Resultado                                       |
| ---------------------------------------------------- | ----------------------------------------------- |
| same-origin (incluye `ws://`/`wss://` al mismo host) | normal, sin hallazgo                            |
| `AllowedOrigins`                                     | normal, sin hallazgo                            |
| origen externo desconocido                           | **medium** (45; WebSocket 55)                   |
| conexión no cifrada desde página `https`             | +15 → **high**                                  |
| `BlockedOrigins`                                     | **critical** (prioridad sobre `AllowedOrigins`) |

### ScriptInjectionDetector

| Situación                                      | Resultado |
| ---------------------------------------------- | --------- |
| script externo de `AllowedScriptOrigins`       | info      |
| script same-origin dinámico                    | info      |
| script inline insertado dinámicamente          | low       |
| script externo desconocido (con `integrity`)   | medium    |
| script externo desconocido **sin `integrity`** | high      |
| script con `src` `data:` o `javascript:`       | high      |
| script desde `BlockedOrigins`                  | critical  |
| `iframe` dinámico a origen desconocido         | medium    |
| `object`/`embed` dinámico a origen desconocido | high      |

Los scripts insertados por el parser HTML (el HTML original de la página) no se reportan
como dinámicos.

### CspViolationDetector

Toda violación es al menos `low`. Las que afectan directivas de scripts suben a `medium`, el modo
report-only resta riesgo y un origen bloqueado la eleva a `critical`.

### PrototypePollutionDetector

No todo cambio es crítico: un polyfill que agrega un método a `Array.prototype` es `low`.
El riesgo aumenta si la propiedad es típica de payloads (`__proto__`, `constructor`,
`prototype`, `isAdmin`, `role`, `permissions`, `polluted`, ...), si el prototipo es
`Object.prototype`, o si se reemplaza o elimina una función nativa.
Ejemplo: `Object.prototype.polluted = true` → **critical**.

### RuntimeIntegrityDetector

| Situación                                                                 | Resultado |
| ------------------------------------------------------------------------- | --------- |
| reemplazo por algo que parece nativo (Proxy, `bind`)                      | medium    |
| reemplazo por una función no nativa                                       | high      |
| reemplazo no nativo de `eval`, `Function` o `Function.prototype.toString` | critical  |
| función ya modificada al iniciar BrowserGuard                             | medium    |
| función eliminada                                                         | medium    |

`NativeFunctionUtils` no depende solo de `Function.prototype.toString()`: combina el código
fuente obtenido con una referencia **capturada** de `toString` (inmune a reemplazos posteriores),
la presencia de un `toString` propio (técnica de ocultamiento), la presencia inesperada de
`prototype`, la coincidencia de `name` y la comparación de referencias contra el baseline.

### XssSinkDetector (DOM XSS)

`SinkMonitor` observa las APIs que convierten un string en HTML o código: los setters de
`innerHTML` y `outerHTML` (en elementos y shadow roots), `insertAdjacentHTML`, `document.write` /
`writeln`, `Range.createContextualFragment`, `iframe.srcdoc`, `setAttribute` (handlers de eventos
y URLs `javascript:`) y `setTimeout` / `setInterval` llamados con un **string**.

Escribir HTML es normal, así que solo se reporta contenido con **indicadores**:

| Indicador                                                                            | Peso |
| ------------------------------------------------------------------------------------ | ---- |
| Handler que se ejecuta sin interacción (`onerror`, `onload`, `onfocus`, ...)         | 50   |
| Valor tomado de la URL de la página (query o hash) escrito en el sink                | 45   |
| URL `javascript:` (también codificada con entidades; se ignora `javascript:void(0)`) | 45   |
| Elemento `<script>`                                                                  | 40   |
| Handler inline que requiere interacción (`onclick`, ...)                             | 30   |
| Código pasado como string a `setTimeout` / `setInterval`                             | 30   |
| Acceso a datos sensibles u ofuscación (`document.cookie`, storage, `atob`)           | 30   |
| Prueba de concepto (`alert(`, `prompt(`, `confirm(`)                                 | 25   |
| Contenido embebido (`iframe`, `object`, `embed`, `base`, `srcdoc`)                   | 20   |
| `document.write` (sink obsoleto)                                                     | +10  |

Ejemplos: `<button onclick="save()">` → low; `<img src=x onerror=alert(1)>` → high; el mismo
payload tomado de `?q=` en la URL (XSS reflejado en el DOM) → critical.

Solo se registra el sink, el elemento, la longitud y los nombres de los indicadores: **nunca el
contenido**. Las escrituras idénticas se agrupan durante 10 segundos para que un bucle de
renderizado no inunde el historial.

> **No se interceptan a propósito: `eval` y `new Function`.** Reemplazar `eval` cambia la
> semántica del lenguaje (un `eval` _directo_ solo ve las variables locales si es la función
> original), y reemplazar `Function` rompe comprobaciones como `fn.constructor === Function`.
> Eso alteraría la aplicación. Su uso sigue siendo visible mediante violaciones CSP de
> `unsafe-eval` y `RuntimeMonitor`; la cobertura completa está prevista con Trusted Types (v0.3).

### Personalizar pesos

```ts
BrowserGuard.Start({
  Risk: {
    Weights: {
      "script.missing-integrity": 40, // exigir SRI con más rigor
      "network.websocket": 0,
    },
  },
});
```

Señales disponibles: `network.unknown-origin`, `network.blocked-origin`, `network.websocket`,
`network.insecure-transport`, `script.dynamic`, `script.external`, `script.inline`,
`script.unknown-origin`, `script.missing-integrity`, `script.blocked-origin`,
`script.dangerous-scheme`, `dom.embedded-content`, `dom.unknown-origin`, `dom.plugin-content`,
`dom.blocked-origin`, `csp.violation`, `csp.script-directive`, `csp.report-only`,
`csp.blocked-origin`, `prototype.added`, `prototype.removed`, `prototype.modified`,
`prototype.suspicious-key`, `prototype.object-root`, `prototype.native-overridden`,
`runtime.modified`, `runtime.preexisting`, `runtime.removed`, `runtime.non-native`,
`runtime.critical-target`, `xss.auto-event-handler`, `xss.event-handler`, `xss.script-tag`,
`xss.javascript-url`, `xss.embedded-content`, `xss.sensitive-access`, `xss.probe`,
`xss.url-reflected`, `xss.string-code`, `xss.legacy-sink`, y las señales `bot.*` de
[Anti-scraping](#señales).

## Eventos

| Evento                                      | Se emite para                                                      |
| ------------------------------------------- | ------------------------------------------------------------------ |
| `Finding`                                   | todo hallazgo que supera el umbral configurado                     |
| `Threat`                                    | hallazgos de severidad `low` o superior (excluye los informativos) |
| `Critical`, `High`, `Medium`, `Low`, `Info` | hallazgos de esa severidad exacta                                  |
| `Bot`                                       | cambio del veredicto anti-scraping (recibe un `BotAssessment`)     |

```ts
Guard.On("Threat", Handler);

Guard.On("Critical", (Finding) => {
  SendToSiem(Finding);
});
```

El EventBus interno no se expone. Si un manejador de tu aplicación lanza una excepción, no
interrumpe a BrowserGuard ni a los demás manejadores; el error se reporta con `reportError`
(igual que un listener del DOM), por lo que sigue siendo visible.

### Salida en consola

La consola del navegador es visible para cualquier usuario final. Por eso, fuera de
`development`, BrowserGuard **no imprime hallazgos**: solo muestra un aviso una vez por página
(modo `"notice"`) y entrega los hallazgos a tu código mediante `On()`. Así el usuario sabe que la
página está protegida, pero no ve qué se detectó, qué orígenes conoces ni cómo funciona tu
configuración.

```ts
BrowserGuard.Start({
  Preset: "strict", // Console: "notice" por defecto
  Notice: {
    Title: "Monitoreo de seguridad activo",
    Message:
      "La actividad sospechosa en esta página se detecta y se reporta al proveedor del sitio. " +
      "No pegues ni ejecutes aquí código que no entiendas.",
  },
});
```

El texto por defecto describe con precisión lo que se monitorea (el comportamiento de seguridad de
la página, no la actividad personal del usuario) e incluye la advertencia habitual contra
_self-XSS_. Si lo personalizas, evita afirmaciones más amplias que lo que realmente se registra.

> El navegador sigue mostrando sus propios mensajes (por ejemplo, las violaciones CSP o los errores
> de red). Esos no los genera BrowserGuard y no pueden suprimirse desde JavaScript.

Para recibir los hallazgos como proveedor, envíalos a tu backend (ver
[Enviar hallazgos a tu backend](#enviar-hallazgos-a-tu-backend)).

Con `Console: "findings"` (por defecto en `development`), `ConsoleReporter` usa `console.group` (expandido) con `console.error` para `critical`/`high`,
`console.groupCollapsed` con `console.warn` para `medium` y con `console.info` para `low`/`info`.
Para no llenar la consola, respeta el umbral del preset y suprime hallazgos equivalentes
(misma categoría, título y origen) durante 10 segundos.

```text
╔════════════════════════════════════════╗
║ BrowserGuard                           ║
╚════════════════════════════════════════╝

HIGH SECURITY EVENT

Category:
script-injection

Unknown external script without integrity
A <script> element pointing to https://cdn.unknown.example (unknown) was inserted dynamically.

Origin:
https://cdn.unknown.example

Risk:
65 / 100
```

Los stack traces se limpian de frames internos:

```text
submitPayment() Payment.ts:82:5
onClick() Checkout.tsx:143:9
```

## Ejemplos

### Vite + React

```ts
// SecurityBootstrap.ts
import { BrowserGuard } from "@puertochenta/browser-guard";

export const Guard = BrowserGuard.Start({
  Preset: "strict",
});
```

```tsx
// main.tsx
import "./SecurityBootstrap";

import React from "react";
import ReactDOM from "react-dom/client";

import App from "./App";

ReactDOM.createRoot(document.getElementById("root")!).render(<App />);
```

### Vue

```ts
// main.ts
import "./SecurityBootstrap";
import { createApp } from "vue";
import App from "./App.vue";

createApp(App).mount("#app");
```

### Angular

```ts
// main.ts
import "./SecurityBootstrap";
import { bootstrapApplication } from "@angular/platform-browser";
import { AppComponent } from "./app/app.component";

bootstrapApplication(AppComponent);
```

> Angular usa zone.js, que envuelve `fetch`, `XMLHttpRequest`, `setTimeout` y otras APIs.
> Si BrowserGuard se inicia después de zone.js, `RuntimeMonitor` reportará esas funciones como
> modificadas antes del inicio. Puedes deshabilitarlo con `Monitors: { Runtime: false }` o ajustar
> el peso de `runtime.preexisting`.

### Next.js / Nuxt (SSR)

El import es seguro en el servidor: sin `window`, `Start()` retorna una instancia inerte.
Inicia BrowserGuard en código que se ejecute en el cliente:

```tsx
// app/SecurityProvider.tsx (Next.js App Router)
"use client";
import { BrowserGuard } from "@puertochenta/browser-guard";

BrowserGuard.Start({ Preset: "balanced" });

export function SecurityProvider({ children }: { children: React.ReactNode }) {
  return children;
}
```

```ts
// plugins/browser-guard.client.ts (Nuxt)
import { BrowserGuard } from "@puertochenta/browser-guard";

export default defineNuxtPlugin(() => {
  BrowserGuard.Start({ Preset: "balanced" });
});
```

### Enviar hallazgos a tu backend

Agrega el plugin `RemoteReporting` y BrowserGuard enviará los hallazgos a tu servidor (ver
[Envío remoto](#envío-remoto)):

```ts
import { BrowserGuard } from "@puertochenta/browser-guard";
import { RemoteReporting } from "@puertochenta/browser-guard/remote";

BrowserGuard.Start({
  Preset: "strict",
  Plugins: [
    RemoteReporting({
      Endpoint: "https://security.example.com/browser-guard/findings",
      Metadata: { App: "checkout", Version: "2.4.1", Environment: "production" },
    }),
  ],
});
```

Si prefieres tu propio mecanismo, suscríbete a los eventos o registra un reporter propio:

```ts
Guard.On("Critical", (Finding) => {
  MyMonitoring.CaptureSecurityEvent(Finding);
});

BrowserGuard.Start({
  Reporters: [{ Name: "Siem", Report: (Finding) => MySiem.Send(Finding) }],
});
```

### Modo forense

```ts
const Guard = BrowserGuard.Start({ Preset: "forensic", Forensic: { MaxEvents: 2000 } });

// Más tarde, por ejemplo ante un hallazgo crítico:
Guard.On("Critical", () => {
  const Timeline = Guard.GetTimeline(); // eventos recientes, incluidos los normales
});
```

### Demo

El repositorio incluye una demo interactiva en [`examples/vite-demo`](examples/vite-demo) con botones
que provocan eventos controlados: fetch permitido, fetch externo, origen bloqueado, WebSocket,
script dinámico, script inline, violación CSP, modificación de prototipo y del runtime.

La demo envía los hallazgos al colector de ejemplo [`examples/collector`](examples/collector), un
servidor Node sin dependencias que los imprime en la terminal, los guarda en
`data/findings.jsonl` y los muestra en un panel en `http://127.0.0.1:8787/`.

```bash
# Terminal 1: colector (lo que ve el proveedor)
cd examples/collector
pnpm start

# Terminal 2: demo (lo que ve el usuario final)
cd examples/vite-demo
pnpm install
pnpm dev
```

## Plugins

Las funciones opcionales se publican como plugins en sus propias rutas del paquete. Si no
importas un plugin, su código no entra en tu bundle.

```ts
import { BrowserGuard } from "@puertochenta/browser-guard";
import { AntiScraping } from "@puertochenta/browser-guard/anti-scraping";
import { RemoteReporting } from "@puertochenta/browser-guard/remote";

BrowserGuard.Start({
  Preset: "strict",
  Plugins: [AntiScraping(), RemoteReporting({ Endpoint: "https://security.example.com/findings" })],
});
```

| Plugin            | Ruta                                        | Agrega (min+gzip) |
| ----------------- | ------------------------------------------- | ----------------- |
| núcleo            | `@puertochenta/browser-guard`               | 15,7 KB           |
| `AntiScraping`    | `@puertochenta/browser-guard/anti-scraping` | +4,2 KB           |
| `RemoteReporting` | `@puertochenta/browser-guard/remote`        | +2,0 KB           |

`GetStatus().Plugins` indica si cada plugin quedó activo; por ejemplo, `RemoteReporting` con un
endpoint inválido queda inactivo:

```ts
Guard.GetStatus().Plugins; // [{ Name: "AntiScraping", Active: true }, { Name: "RemoteReporting", Active: false }]
```

Un plugin que falla al instalarse queda inactivo y nunca afecta a los demás ni a la aplicación.
Los nombres repetidos se ignoran (gana el primero).

### Escribir un plugin propio

Un plugin recibe un `PluginHost` antes de que inicien los monitores: puede agregar monitores,
detectores y reporters, o reaccionar a cada candidato de detección.

```ts
import type { GuardPlugin } from "@puertochenta/browser-guard";

export function AuditTrail(): GuardPlugin {
  return {
    Name: "AuditTrail",
    Setup(host) {
      host.AddReporter({ Name: "AuditReporter", Report: (Finding) => MyAudit.Log(Finding) });
      host.OnCandidate((Candidate) => MyAudit.Count(Candidate.Category));
      host.OnDispose(() => MyAudit.Flush());
      return true; // activo
    },
  };
}
```

## Envío remoto

El plugin `RemoteReporting` (`@puertochenta/browser-guard/remote`) envía los hallazgos a tu
endpoint. Sin él, nada sale del navegador.

```ts
BrowserGuard.Start({
  Plugins: [RemoteReporting({ Endpoint: "https://security.example.com/findings" })],
});
```

```ts
interface RemoteConfig {
  Endpoint: string; // https, mismo origen o http://localhost
  MinSeverity?: Severity; // por defecto: "low"
  BatchSize?: number; // 1 - 100. Por defecto: 20
  FlushIntervalMs?: number; // 1000 - 60000. Por defecto: 5000
  MaxQueue?: number; // 10 - 5000. Por defecto: 200
  MaxRetries?: number; // 0 - 10. Por defecto: 3
  Headers?: Record<string, string>; // visibles en el cliente: no uses secretos
  Metadata?: Record<string, string | number | boolean>; // versión, entorno, ...
  IncludeStack?: boolean; // por defecto: true
  IncludeEvidence?: boolean; // por defecto: true
  IncludePagePath?: boolean; // por defecto: true
}
```

**Cómo envía:**

- En lotes: al juntar `BatchSize` hallazgos o al vencer `FlushIntervalMs`. Sin hallazgos
  pendientes no hay timers activos.
- Al ocultar o cerrar la página, y al llamar a `Stop()`, envía la cola pendiente con
  `navigator.sendBeacon` (o `fetch` con `keepalive` si configuraste `Headers`).
- Ante errores de red, `5xx`, `408` o `429` reintenta con backoff exponencial (máximo 60 s).
  Otros errores, o reintentos agotados, descartan el lote.
- Cada payload pesa como máximo ~60 KB (límite de `keepalive`/`sendBeacon`). Un hallazgo que no
  cabe se envía sin evidencia ni stack.
- Los envíos propios usan el `fetch` original, capturado antes de interceptarlo: no generan
  hallazgos ni bucles.

**Payload** (`POST`, cuerpo JSON):

```json
{
  "Schema": "browser-guard.findings/v1",
  "SentAt": 1760000000000,
  "SessionId": "3f0c1d9e-…",
  "Page": { "Origin": "https://shop.example.com", "Path": "/checkout" },
  "Metadata": { "App": "checkout", "Version": "2.4.1" },
  "Findings": [{ "Id": "…", "Severity": "high", "Title": "…", "RiskScore": 65, "...": "..." }]
}
```

`SessionId` es aleatorio por cada `Start()` y solo sirve para agrupar los hallazgos de una
misma carga de página; no se persiste ni identifica al usuario.

**Tu endpoint debe:**

- aceptar `POST` con `Content-Type: application/json` **y** `text/plain` (usado por
  `sendBeacon`), parseando el cuerpo como JSON en ambos casos;
- responder a CORS (preflight `OPTIONS`) si está en otro origen;
- permitirse en la directiva `connect-src` de tu CSP;
- tratar todo lo recibido como **no confiable**: cualquiera puede enviar hallazgos falsos a
  un endpoint público. Valida el esquema, limita tamaño y frecuencia, y escapa los datos al
  mostrarlos. El [colector de ejemplo](examples/collector/server.mjs) muestra estas prácticas.

`GetStatus().Remote` expone los contadores `{ Queued, Sent, Dropped, Failed }`.

## Anti-scraping

Detección de navegadores automatizados y de comportamiento de scraping, con reacciones
configurables, mediante el plugin `AntiScraping` (`@puertochenta/browser-guard/anti-scraping`).

```ts
import { BrowserGuard } from "@puertochenta/browser-guard";
import { AntiScraping } from "@puertochenta/browser-guard/anti-scraping";
import { RemoteReporting } from "@puertochenta/browser-guard/remote";

const Guard = BrowserGuard.Start({
  Preset: "strict",
  Plugins: [AntiScraping(), RemoteReporting({ Endpoint: "https://security.example.com/findings" })],
});

Guard.On("Bot", (Assessment) => {
  // { Verdict: "unknown" | "human" | "suspicious" | "bot", Score, Signals, UpdatedAt }
});
```

### Qué puede y qué no puede hacer

> **Ninguna protección del lado del cliente detiene todo el scraping.** La mayoría de los
> scrapers (curl, Python `requests`, Scrapy) descargan el HTML o llaman a tus APIs **sin ejecutar
> JavaScript**: BrowserGuard nunca se carga en ellos. Y un navegador automatizado puede bloquear
> o neutralizar cualquier script. Úsalo como una capa más, junto con protección en el servidor
> (rate limiting, autenticación de APIs, un servicio de gestión de bots).

Lo que BrowserGuard aporta:

| Capa      | Qué hace                                                                                                                                                       |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Detección | Identifica automatización y comportamiento de bot en navegadores reales.                                                                                       |
| Contenido | Retira del DOM el contenido marcado como protegido cuando la sesión es un bot.                                                                                 |
| Servidor  | Envía un header con el veredicto: tu API puede rechazar bots **y clientes que no ejecutan BrowserGuard**, que es como se detectan los scrapers sin JavaScript. |

Validado contra Chrome y Firefox headless: una sesión automatizada estándar se clasifica como
`bot` al cargar; un bot que oculta `webdriver` y el user agent headless no se detecta al cargar,
pero sí en cuanto hace un barrido de URLs y genera eventos sintéticos.

### Señales

| Grupo (`Signals`) | Señal                                                                                  | Peso         |
| ----------------- | -------------------------------------------------------------------------------------- | ------------ |
| `Automation`      | `navigator.webdriver`                                                                  | 80           |
|                   | Chrome headless / PhantomJS (user agent o Client Hints)                                | 70           |
|                   | Rastros de Selenium, chromedriver, Puppeteer/Playwright, PhantomJS, Nightmare, Cypress | 80           |
| `Environment`     | Renderizado WebGL por software (SwiftShader, llvmpipe)                                 | 25           |
|                   | User agent que no coincide con la plataforma, o Chrome sin `window.chrome`             | 25           |
|                   | Sin idiomas / ventana de 0×0 / Chrome de escritorio sin plugins                        | 20 / 20 / 10 |
| `RequestRate`     | Barrido secuencial de ids (`/product/1`, `/product/2`, ...)                            | 45           |
|                   | Ráfaga de solicitudes por minuto (`MaxRequestsPerMinute`)                              | 35           |
| `Interaction`     | 10 o más eventos de entrada generados por script (`isTrusted: false`)                  | 30           |
|                   | Pestaña visible 30 s sin mouse, teclado, touch ni scroll                               | 30           |
|                   | Interacción humana real                                                                | −25          |

**Veredicto:** `bot` a partir de 70 puntos, `suspicious` a partir de 40; por debajo, `human` si
hubo interacción real, o `unknown`. La interacción humana solo compensa señales pasivas (entorno,
falta de interacción): no compensa automatización ni comportamiento automatizado (barridos,
ráfagas, eventos sintéticos). El veredicto `bot` es definitivo para la sesión. Los pesos se
ajustan con `Risk.Weights`.

**Privacidad:** las comprobaciones de entorno comparan valores del navegador (renderer WebGL,
idiomas, plataforma) y **descartan** esos valores: solo se registran y envían nombres de señal
como `env-software-gl`. No se calcula ni transmite una huella identificable. La interacción se
mide con contadores por tipo de evento: nunca teclas, coordenadas ni elementos.

### Reacciones

**1. Contenido protegido.** Marca los elementos sensibles con `data-guard-protect`:

```html
<div data-guard-protect>Precio mayorista: $1.249,00 · Stock: 312</div>
```

Cuando el veredicto alcanza `ProtectAt` (por defecto `bot`), su contenido se **retira del DOM**
(no solo se oculta: un scraper lee el DOM, no la pantalla) y se reemplaza por `Placeholder`.
`Stop()` lo repone intacto. También se protegen los elementos insertados después.

En React, Vue o Angular no muevas nodos que administra el framework: consulta el veredicto y no
renderices los datos sensibles.

```tsx
const Assessment = BrowserGuard.GetBotAssessment();
return Assessment?.Verdict === "bot" ? <Unavailable /> : <PriceTable />;
```

**2. Header de veredicto.** Cada solicitud `fetch`/`XHR` al propio origen (y a
`VerdictHeader.Origins`) lleva:

```text
X-BrowserGuard-Verdict: human; score=0; sid=3f0c1d9e-…
```

Ejemplo de uso en el servidor (Express):

```ts
app.use("/api", (req, res, next) => {
  const verdict = req.get("X-BrowserGuard-Verdict")?.split(";")[0];
  if (!verdict) return res.status(403).end(); // no ejecutó BrowserGuard: curl, Scrapy...
  if (verdict === "bot") return res.status(403).end();
  if (verdict === "suspicious") return res.status(429).end(); // o pedir un captcha
  next();
});
```

> El header puede **falsificarse**: un scraper que lo conozca puede enviarlo con valor `human`.
> Sirve para descartar el scraping sin JavaScript y los bots detectados, pero debe combinarse con
> rate limiting por sesión (`sid`) e IP. Para orígenes externos, el header dispara un preflight
> CORS: ese servidor debe permitirlo en `Access-Control-Allow-Headers`.

**3. Reporte.** Cada detección genera un hallazgo de categoría `bot`, que llega a `On()`,
al historial y al envío remoto. `GetStatus()` incluye `Bot` y `SessionId`.

### Configuración

```ts
interface AntiScrapingConfig {
  Enabled?: boolean; // por defecto: true (false lo desactiva sin quitarlo, p. ej. en tests e2e)
  Signals?: {
    Automation?: boolean;
    RequestRate?: boolean;
    Interaction?: boolean;
    Environment?: boolean;
  };
  MaxRequestsPerMinute?: number; // 10 - 10000. Por defecto: 120
  SequentialThreshold?: number; // 3 - 1000. Por defecto: 10
  ProtectSelector?: string; // por defecto: "[data-guard-protect]"
  ProtectAt?: "suspicious" | "bot"; // por defecto: "bot"
  Placeholder?: string; // por defecto: "Content unavailable."
  VerdictHeader?: {
    Enabled?: boolean; // por defecto: true
    Name?: string; // por defecto: "X-BrowserGuard-Verdict"
    Origins?: string[]; // orígenes externos que también reciben el header
  };
}
```

### Falsos positivos a tener en cuenta

- Tests end-to-end (Cypress, Playwright, Selenium) se clasifican como `bot`: usa
  `AntiScraping({ Enabled: false })` en esos entornos.
- Algunos navegadores en máquinas virtuales o sin aceleración gráfica usan renderizado por
  software (`env-software-gl`, 25 puntos: por sí solo no alcanza `suspicious`).
- Usuarios que abren la página en segundo plano no generan `no-interaction` (solo cuenta con la
  pestaña visible).
- Usa `ProtectAt: "bot"` (por defecto) para no retirar contenido a sesiones solo sospechosas.

## Limitaciones

- **Orden de carga.** Solo se observa lo que ocurre después de `Start()`. Código malicioso que
  se ejecuta antes (por ejemplo, un script inyectado en el HTML) puede alterar el entorno sin ser
  visto; `RuntimeMonitor` lo reporta solo si deja funciones con apariencia no nativa.
- **Evasión.** Un atacante con ejecución de código en la página puede, en teoría, detectar y
  desactivar BrowserGuard, usar referencias capturadas antes del inicio, o usar canales no
  observados (`navigator.sendBeacon`, `<img>`, `<link>`, formularios, `EventSource`,
  `WebRTC`, workers). BrowserGuard aumenta la visibilidad; no es una barrera.
- **Realms.** Solo se observa la ventana principal. Iframes y workers tienen sus propios
  `fetch`, prototipos y DOM.
- **Proxies.** Un `Proxy` sobre una función nativa reporta `[native code]`; por eso los reemplazos
  se detectan principalmente por comparación de referencias.
- **Verificación periódica.** Los cambios en prototipos y funciones críticas se detectan en el
  siguiente ciclo de verificación (2-5 s según preset), no en el momento exacto. Un cambio que se
  revierte antes del siguiente ciclo puede pasar inadvertido.
- **DOM.** Modificar el `src` de un script existente no se detecta (los cambios de atributos no se
  observan, salvo mediante `setAttribute`). Tampoco se observan atributos asignados como
  propiedades (`img.onerror = ...`, `a.href = "javascript:..."`). Los eventos de inserción de
  elementos no incluyen stack trace (el callback de `MutationObserver` es asíncrono); los
  hallazgos de sinks sí.
- **DOM XSS.** La detección se basa en indicadores, no en un seguimiento completo de datos
  (taint tracking): un payload codificado o transformado puede no reconocerse como reflejado, y
  `eval` / `new Function` no se interceptan (ver [XssSinkDetector](#xsssinkdetector-dom-xss)).
- **Falsos positivos.** Librerías de observabilidad (Sentry, Datadog, zone.js) envuelven `fetch`/XHR
  legítimamente y pueden reportarse como `runtime-integrity`. Polyfills que extienden prototipos
  se reportan como `low`. Usa `AllowedOrigins`, presets y `Risk.Weights` para ajustarlo.
- **URLs desconocidas.** Para no ejecutar código de la aplicación, solo se interpretan destinos
  `string`, `URL` y `Request`; otros objetos se registran como `[unknown]`.
- **CSP.** `CspMonitor` solo funciona si la página tiene una política CSP.
- **Anti-scraping.** No detiene scrapers sin JavaScript ni bots que neutralicen el script;
  la paginación por query string (`?page=2`) no se detecta como barrido, porque la query se
  descarta por privacidad. Ver [Anti-scraping](#anti-scraping).

## Seguridad

BrowserGuard se diseñó para no convertirse en una fuente de fuga de información:

- **Nunca registra** contraseñas, cookies, headers (incluido `Authorization`), cuerpos HTTP,
  contenido de formularios, contenido de scripts inline, clipboard ni pulsaciones de teclado.
- **URLs saneadas:** se almacenan sin query string, fragmento ni credenciales (`user:pass@`),
  porque los tokens suelen viajar en la query. Solo se indica `HasQuery: true`. Las URLs
  `data:`, `blob:` y `javascript:` se registran solo con su esquema.
- **Evidencia saneada:** toda evidencia pasa por `SafeSerializer`, que censura claves sensibles
  (`password`, `token`, `secret`, `cookie`, `authorization`, `session`, `apiKey`, `cardNumber`,
  `cvv`, ...) y valores con forma de JWT, `Bearer` o números de tarjeta, y limita profundidad y tamaño.
- **Local por defecto.** Sin telemetría. Nada sale del navegador salvo que agregues el plugin
  `RemoteReporting` (solo `https`, mismo origen o `localhost`) o lo envíes tú mismo. El envío
  remoto nunca incluye cookies (`credentials: "omit"`) ni el header `Referer`, y la ruta de la
  página va sin query string.
- **Sin fingerprinting.** Las comprobaciones opcionales de `AntiScraping` comparan
  propiedades del navegador y descartan los valores: solo se registran nombres de señal, nunca
  una huella identificable.
- **Aislamiento de errores.** Cualquier error interno se contabiliza en
  `GetStatus().InternalErrors` y nunca se propaga a la aplicación.
- **Memoria acotada.** Historial, línea de tiempo, cola de eventos (1000) y caché de
  deduplicación tienen límites fijos.

Para reportar una vulnerabilidad, ver [SECURITY.md](SECURITY.md).

## Performance

Decisiones con impacto en rendimiento:

| Punto                                           | Decisión                                                                                                                                                                                                                |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hot path (`fetch`, `XHR.send`, `new WebSocket`) | El hook solo construye un evento pequeño y captura el stack. La detección, el puntaje y el reporte se difieren a una microtask y se procesan en lote.                                                                   |
| Stack traces                                    | Solo en los puntos de interceptación de red, limitados a 8-16 frames. Nunca en callbacks masivos.                                                                                                                       |
| `MutationObserver`                              | Solo `childList` + `subtree`; sin `attributes` ni `characterData`. Un único `querySelectorAll` por subárbol insertado, y solo si tiene hijos.                                                                           |
| Prototipos y runtime                            | Sin polling agresivo: comparación por referencia de ~150 descriptores y 11 funciones cada 2-5 s, ejecutada con `requestIdleCallback` cuando está disponible y encadenando `setTimeout` (nunca se acumulan ejecuciones). |
| Serialización                                   | Solo de la evidencia de hallazgos, con profundidad, claves y longitud acotadas.                                                                                                                                         |
| Consola                                         | Umbral por preset y deduplicación de 10 s.                                                                                                                                                                              |
| Ráfagas                                         | La cola de eventos descarta por encima de 1000 eventos pendientes (`GetStatus().DroppedEvents`).                                                                                                                        |

Medición de referencia (Chrome, demo de este repositorio): el overhead por llamada a `fetch`
interceptada es de aproximadamente **50 µs**, dominado por la captura del stack trace; en
`XMLHttpRequest.open` es imperceptible. Tamaño del bundle de una aplicación que importa solo el
núcleo: ~49 KB minificado, ~16 KB gzip, sin dependencias; cada plugin suma lo suyo (ver
[Plugins](#plugins)). En bundles de producción (librería y app en el mismo archivo) los stack
traces siguen apuntando a tu código: los frames internos se descartan por posición, no por nombre
de archivo.

## Arquitectura

```text
BrowserGuard
    ↓  registra e inicia
Monitors ──────────── observan y generan SecurityEvent (sin decidir nada)
    ↓  GuardContext: cola + microtask
EventBus (interno)
    ↓
Detectors ─────────── analizan eventos y producen candidatos con señales
    ↓
RiskEngine ────────── señales → puntaje 0-100 → severidad → SecurityFinding
    ↓
Historial + eventos públicos + Reporters
```

```text
src/
├── BrowserGuard.ts           # fachada pública y orquestación
├── Index.ts                  # exports públicos
├── Config/                   # presets y resolución de configuración
├── Core/                     # EventBus, RiskEngine, GuardContext, MonitorRegistry,
│                             # FunctionPatch, FindingHistory, RiskSignals, Components,
│                             # PluginManager, BotSession, AntiScrapingController
├── Plugins/                  # puntos de entrada: AntiScraping, RemoteReporting
├── Types/                    # tipos públicos e internos
├── Monitors/                 # Fetch, Xhr, WebSocket, Dom, Csp, Prototype, Runtime,
│                             # Automation, Interaction
├── Detectors/                # Network, ScriptInjection, CspViolation,
│                             # PrototypePollution, RuntimeIntegrity, Bot
├── Protection/               # ContentShield (anti-scraping)
├── Reporters/                # Reporter, ConsoleReporter, ConsoleNotice,
│                             # RemoteReporter, RemoteTransport
└── Utils/                    # StackTrace, UrlUtils, SafeSerializer, NativeFunctionUtils,
                              # RingBuffer, PeriodicTask, IdGenerator, AutomationSignals
```

Para agregar un monitor: implementa `Monitor` (o extiende `BaseMonitor`), emite eventos con
`GuardContext.Emit()` y regístralo en `Core/Components.ts`. Para agregar un detector: implementa
`Detector`, declara los tipos de evento en `Handles` y retorna un `FindingCandidate` con señales.

## Desarrollo

Requiere Node 22.12 o superior (ver `.nvmrc`) y pnpm.

```bash
pnpm install
pnpm build          # tsup → dist/index.js + dist/index.d.ts
pnpm typecheck      # tsc (src + tests, y e2e con tipos de Node)
pnpm lint           # eslint (typescript-eslint strict)
pnpm test           # vitest (watch)
pnpm test:run       # tests unitarios (jsdom)
pnpm test:coverage  # cobertura (umbral 80% en Core y Detectors)
pnpm test:e2e       # compila y prueba dist/ en Chromium y Firefox reales (Playwright)
pnpm test:package   # empaqueta el .tgz, lo instala en un proyecto temporal y verifica los tipos
pnpm format         # prettier
```

La primera vez, instala los navegadores de Playwright: `pnpm exec playwright install chromium firefox`.

**Dos niveles de tests:**

- **Unitarios (Vitest + jsdom):** lógica de detección, puntaje, configuración y ciclo de vida.
  jsdom no implementa CSP y define en JavaScript funciones que en un navegador son nativas,
  por lo que esos casos se simulan y se documentan en cada test.
- **End-to-end (Playwright):** prueban el bundle compilado (lo que se publica) en navegadores
  reales: violaciones CSP reales, detección de funciones nativas, stack traces limpios (también
  con la librería empaquetada junto con la app), restauración con `Stop()`, detección de
  navegadores automatizados, header de veredicto y envío remoto.
- **Paquete (`test:package`):** instala el tarball como lo haría un usuario y verifica los tipos
  de cada ruta con resolución `Bundler`, `NodeNext` y `Node10`; luego las importa en Node (SSR).

**CI** (`.github/workflows/ci.yml`): formato, lint, tipos, tests unitarios con cobertura, build y
verificación del paquete en Node 22 y 24; tests e2e en Chromium y Firefox; build de los ejemplos.

**Versionado y publicación** con [changesets](https://github.com/changesets/changesets):

```bash
pnpm changeset   # describe tu cambio (patch / minor / major)
```

Al integrar en `main`, el workflow `release.yml` abre un PR con la nueva versión y el
CHANGELOG; al integrar ese PR, publica en npm con
[provenance](https://docs.npmjs.com/generating-provenance-statements). Requiere el secreto
`NPM_TOKEN` en el repositorio. Por la configuración de provenance, la publicación se hace desde CI,
no desde una máquina local.

## Roadmap

Incluido en 0.1.0: monitores de red, DOM, CSP, prototipos e integridad del runtime; sistema de
plugins; plugins `RemoteReporting` y `AntiScraping`; reporters propios (`Reporters`).

- **v0.2:** detección de DOM XSS en sinks peligrosos: `innerHTML`, `outerHTML`, `document.write`,
  `insertAdjacentHTML`, `setAttribute`, timers con string (✅ disponible: `SinkMonitor`).
- **v0.3:** integración con Trusted Types.
- **v0.4:** análisis de Subresource Integrity y monitoreo de supply chain.
- **v0.5:** línea de tiempo forense avanzada.
- **v0.6:** integraciones listas para SIEM específicos; token anti-scraping verificable en el servidor.
- **v1.0:** Browser Runtime Security Platform.

La prevención activa de red y scripts (detect + prevent) podrá evaluarse en versiones futuras;
hoy BrowserGuard detecta y reporta (la única reacción activa es la protección de contenido
opcional de `AntiScraping`).

## Licencia

[MIT](LICENSE) © @puertochenta
