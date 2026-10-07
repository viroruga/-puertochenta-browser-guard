Quiero que construyas desde cero un paquete NPM en TypeScript orientado a seguridad del lado cliente.

El objetivo del proyecto es crear una librería de **Browser Runtime Security / Client-Side Intrusion Detection**, capaz de ejecutarse dentro del navegador y analizar comportamientos potencialmente sospechosos durante la ejecución de una aplicación web.

El paquete NO debe prometer detectar “cualquier ataque” ni reemplazar soluciones como WAF, CSP, EDR, SIEM o herramientas de seguridad del backend.

Su propósito será observar el runtime del navegador y detectar indicadores de comportamiento sospechoso relacionados con:

- manipulación del DOM;
- inyección dinámica de scripts;
- conexiones de red inesperadas;
- modificación de funciones nativas;
- prototype pollution;
- violaciones CSP;
- uso de WebSocket;
- XMLHttpRequest;
- fetch;
- manipulación de elementos sensibles;
- posibles comportamientos compatibles con XSS;
- modificaciones inesperadas del runtime;
- actividad potencialmente relacionada con exfiltración de información.

El proyecto debe estar diseñado como una librería profesional, extensible, modular y publicable en npm.

## Nombre inicial

Utilizar temporalmente:

```text
@diforte/browser-guard
```

No acoplar internamente la arquitectura al nombre, para permitir renombrarlo posteriormente.

## Stack tecnológico

Utilizar:

```text
TypeScript
pnpm
tsup
Vitest
ESLint
Prettier
```

El paquete debe soportar inicialmente:

```text
ESM
TypeScript types
Tree shaking
Browser moderno
Vite
React
Vue
Angular
Vanilla JavaScript
```

No implementar dependencias de frameworks.

La librería debe ser completamente framework-agnostic.

## Reglas generales del proyecto

Todo el código debe:

- utilizar TypeScript estricto;
- tener arquitectura modular;
- utilizar principios SOLID cuando corresponda;
- evitar archivos excesivamente grandes;
- evitar dependencias innecesarias;
- evitar código duplicado;
- evitar variables globales innecesarias;
- preservar completamente el comportamiento original del navegador;
- manejar correctamente excepciones internas;
- nunca bloquear la aplicación host;
- evitar introducir memory leaks;
- permitir iniciar y detener los monitores;
- restaurar cualquier función interceptada cuando BrowserGuard se detenga.

Los comentarios del código deben escribirse en español.

Los nombres de:

- clases;
- interfaces;
- tipos;
- archivos;

deben utilizar PascalCase cuando corresponda.

Ejemplos:

```text
BrowserGuard.ts
EventBus.ts
RiskEngine.ts
FetchMonitor.ts
DomMonitor.ts
SecurityFinding.ts
```

Variables, propiedades y métodos deben seguir convenciones TypeScript normales.

## Arquitectura

Crear inicialmente esta estructura:

```text
src/
│
├── BrowserGuard.ts
├── Index.ts
│
├── Core/
│   ├── EventBus.ts
│   ├── RiskEngine.ts
│   ├── GuardContext.ts
│   └── MonitorRegistry.ts
│
├── Types/
│   ├── BrowserGuardConfig.ts
│   ├── SecurityEvent.ts
│   ├── SecurityFinding.ts
│   ├── Severity.ts
│   └── Monitor.ts
│
├── Monitors/
│   ├── FetchMonitor.ts
│   ├── XhrMonitor.ts
│   ├── WebSocketMonitor.ts
│   ├── DomMonitor.ts
│   ├── CspMonitor.ts
│   └── PrototypeMonitor.ts
│
├── Detectors/
│   ├── NetworkDetector.ts
│   ├── ScriptInjectionDetector.ts
│   ├── PrototypePollutionDetector.ts
│   └── RuntimeIntegrityDetector.ts
│
├── Reporters/
│   ├── ConsoleReporter.ts
│   └── Reporter.ts
│
└── Utils/
    ├── StackTrace.ts
    ├── UrlUtils.ts
    ├── SafeSerializer.ts
    └── NativeFunctionUtils.ts
```

La arquitectura debe seguir este flujo:

```text
BrowserGuard
    ↓
Monitors
    ↓
EventBus
    ↓
Detectors
    ↓
RiskEngine
    ↓
SecurityFinding
    ↓
Reporters
```

Separar claramente:

```text
captura
detección
evaluación
reporting
```

Un Monitor NO debe decidir directamente si algo es un ataque.

Un Monitor únicamente observa y genera eventos.

Los Detectors analizan esos eventos.

RiskEngine calcula o asigna la severidad.

Reporter presenta el resultado.

## API pública

La API pública debe ser extremadamente simple.

Debe ser posible utilizar la librería así:

```ts
import { BrowserGuard } from "@diforte/browser-guard";

const Guard = BrowserGuard.Start({
  Preset: "strict",
});
```

También:

```ts
Guard.On("Threat", (Finding) => {
  console.log(Finding);
});
```

Y:

```ts
Guard.Stop();
```

Además:

```ts
const Report = Guard.GetReport();
```

La API principal debe incluir:

```text
BrowserGuard.Start()
BrowserGuard.Stop()
BrowserGuard.On()
BrowserGuard.Off()
BrowserGuard.GetReport()
BrowserGuard.GetStatus()
```

`Start()` debe retornar la instancia activa.

Evitar obligar al usuario a crear manualmente cada monitor.

Internamente:

```text
BrowserGuard.Start()
```

debe registrar e iniciar automáticamente todos los monitores habilitados.

## Configuración

Crear una configuración similar a:

```ts
interface BrowserGuardConfig {
  Preset?: "development" | "balanced" | "strict" | "forensic";

  Console?: boolean;

  Monitors?: {
    Fetch?: boolean;
    Xhr?: boolean;
    WebSocket?: boolean;
    Dom?: boolean;
    Csp?: boolean;
    Prototype?: boolean;
  };

  Network?: {
    AllowedOrigins?: string[];
    BlockedOrigins?: string[];
  };

  Dom?: {
    AllowedScriptOrigins?: string[];
  };

  Forensic?: {
    Enabled?: boolean;
    MaxEvents?: number;
  };
}
```

Definir valores por defecto seguros.

## Presets

Implementar:

```text
development
balanced
strict
forensic
```

### development

Mucho detalle.

Puede reportar información, warnings y eventos sospechosos.

### balanced

Nivel recomendado para uso general.

### strict

Solo comportamientos relevantes o de riesgo elevado.

### forensic

Guarda una cronología ampliada de eventos para análisis posterior.

## SecurityEvent

Crear un tipo normalizado para eventos internos.

Ejemplo:

```ts
interface SecurityEvent<T = unknown> {
  Id: string;
  Timestamp: number;
  Type: string;
  Source: string;
  Data: T;
  Stack?: string;
}
```

## SecurityFinding

Los hallazgos deben utilizar una estructura como:

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
    | "dom";

  Severity:
    | "info"
    | "low"
    | "medium"
    | "high"
    | "critical";

  Title: string;

  Description: string;

  RiskScore: number;

  Evidence?: unknown;

  Stack?: string;
}
```

RiskScore debe ser:

```text
0 - 100
```

## EventBus

Crear un EventBus interno liviano.

Debe soportar:

```ts
Emit()
On()
Off()
Once()
```

Debe ser typesafe en la medida de lo posible.

No utilizar una dependencia externa para esto.

## Monitor interface

Crear una interfaz común:

```ts
interface Monitor {
  Name: string;

  Start(): void;

  Stop(): void;

  IsRunning(): boolean;
}
```

Todos los monitores deben implementarla.

## FetchMonitor

Interceptar:

```ts
window.fetch
```

Debe preservar:

- argumentos;
- this context;
- Promise;
- return value;
- errores;
- comportamiento original.

Debe emitir eventos con:

```text
URL
method
origin
timestamp
stack trace
```

NO registrar automáticamente:

```text
Authorization
cookies
passwords
tokens
body completo
```

El sistema debe estar diseñado desde el principio para evitar fuga de información sensible.

Por defecto, los cuerpos HTTP no deben almacenarse.

## XhrMonitor

Interceptar:

```text
XMLHttpRequest.open
XMLHttpRequest.send
```

Debe capturar:

```text
method
URL
origin
timestamp
stack
```

Preservar totalmente el comportamiento original.

## WebSocketMonitor

Interceptar:

```ts
new WebSocket()
```

Registrar:

```text
URL
origin
protocols
stack
```

No inspeccionar mensajes en la primera versión.

Diseñar la arquitectura para permitirlo posteriormente.

## DomMonitor

Utilizar:

```ts
MutationObserver
```

Observar:

```text
script
iframe
object
embed
```

insertados dinámicamente.

Emitir eventos cuando aparecen nuevos elementos.

Para scripts registrar:

```text
src
type
async
defer
integrity
crossOrigin
```

No asumir automáticamente que todos los scripts dinámicos son ataques.

## ScriptInjectionDetector

Analizar eventos provenientes de DomMonitor.

Debe considerar factores como:

```text
script externo
dominio desconocido
ausencia de integrity
script inline
creación dinámica
origen no incluido en AllowedScriptOrigins
```

Calcular un nivel de riesgo.

Ejemplo:

```text
script externo conocido:
info

script externo desconocido:
medium

script desconocido + sin integrity:
high

script sospechoso + dominio bloqueado:
critical
```

Diseñar el cálculo de forma configurable.

## NetworkDetector

Analizar:

```text
fetch
XHR
WebSocket
```

Debe comparar el origen de destino contra:

```text
AllowedOrigins
BlockedOrigins
```

Reglas iniciales:

```text
same-origin:
normal

AllowedOrigins:
normal

unknown external origin:
medium

BlockedOrigins:
critical
```

NO bloquear conexiones inicialmente.

El paquete será inicialmente:

```text
detect + report
```

y no:

```text
detect + prevent
```

La prevención podrá añadirse en versiones futuras.

## CspMonitor

Escuchar:

```ts
securitypolicyviolation
```

Registrar:

```text
blockedURI
violatedDirective
effectiveDirective
sourceFile
lineNumber
columnNumber
disposition
```

Enviar la información al EventBus.

## PrototypeMonitor

Crear un baseline al iniciar para:

```text
Object.prototype
Array.prototype
Function.prototype
String.prototype
Promise.prototype
```

Detectar cambios posteriores.

No utilizar polling extremadamente agresivo.

Diseñar una estrategia eficiente.

Diferenciar entre:

```text
nueva propiedad
propiedad eliminada
descriptor modificado
```

Emitir eventos correspondientes.

## PrototypePollutionDetector

Analizar modificaciones especialmente sospechosas.

Prestar atención a propiedades como:

```text
__proto__
constructor
prototype
isAdmin
role
permissions
polluted
```

No considerar automáticamente todos los cambios como críticos.

## RuntimeIntegrityDetector

Crear un baseline inicial de funciones importantes:

```text
window.fetch
XMLHttpRequest.prototype.open
XMLHttpRequest.prototype.send
WebSocket
setTimeout
setInterval
eval
Function
Element.prototype.appendChild
Element.prototype.setAttribute
```

Detectar modificaciones posteriores.

Debe existir una utilidad:

```text
NativeFunctionUtils
```

para analizar si una función parece nativa.

No depender únicamente de:

```ts
Function.prototype.toString()
```

como única señal.

Combinar diferentes señales.

## Stack traces

Siempre que sea razonable, obtener:

```ts
new Error().stack
```

Crear utilidad:

```text
StackTrace.ts
```

Limpiar las líneas internas del propio BrowserGuard para que el stack mostrado sea útil.

Ejemplo deseado:

```text
Payment.ts:82
submitPayment()
Checkout.tsx:143
```

y no 20 líneas internas de BrowserGuard.

## ConsoleReporter

Crear una salida profesional para consola.

Ejemplo:

```text
╔════════════════════════════════════════╗
║ BrowserGuard                          ║
╚════════════════════════════════════════╝

HIGH SECURITY EVENT

Category:
network

Unknown outbound request

Origin:
https://unknown.example

Risk:
82 / 100

Stack:
Payment.ts:82
```

Utilizar:

```ts
console.groupCollapsed()
console.group()
console.warn()
console.error()
console.info()
```

según severidad.

No llenar la consola innecesariamente.

## Eventos públicos

Permitir:

```ts
Guard.On("Threat", Handler);
```

También:

```text
Finding
Critical
High
Medium
Low
Info
```

Ejemplo:

```ts
Guard.On("Critical", (Finding) => {
  SendToSiem(Finding);
});
```

El EventBus interno no debe exponerse directamente.

## Historial

BrowserGuard debe mantener un historial limitado de:

```text
SecurityFinding
```

Configurable.

Ejemplo:

```ts
Guard.GetReport();
```

debe retornar:

```ts
{
  StartedAt: number;
  Findings: SecurityFinding[];
  Statistics: {
    Total: number;
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Info: number;
  };
}
```

## Forensic Mode

Crear un ring buffer interno.

Ejemplo:

```text
MaxEvents: 1000
```

Guardar eventos internos recientes.

Nunca permitir crecimiento ilimitado de memoria.

En modo forensic:

```ts
Guard.GetTimeline();
```

debe permitir inspeccionar la secuencia reciente.

## Stop()

Esto es extremadamente importante.

Al ejecutar:

```ts
Guard.Stop();
```

se debe:

- desconectar MutationObserver;
- remover listeners CSP;
- restaurar window.fetch;
- restaurar XMLHttpRequest;
- restaurar WebSocket;
- detener PrototypeMonitor;
- limpiar timers internos;
- remover listeners internos cuando corresponda.

La librería debe dejar el entorno en el mismo estado lógico anterior a `Start()`.

## Start idempotente

Si alguien ejecuta:

```ts
BrowserGuard.Start();
BrowserGuard.Start();
```

NO debe duplicar interceptores.

Debe detectar que ya existe una instancia activa.

Definir claramente qué comportamiento tendrá.

Preferencia:

```text
retornar la instancia existente
```

## Seguridad interna

La librería nunca debe:

```text
registrar contraseñas
registrar cookies completas
registrar Authorization headers
registrar JWT completos
capturar contenido completo de formularios
registrar números de tarjetas
interceptar clipboard
enviar datos externamente por defecto
```

Todo debe permanecer local salvo que el desarrollador configure explícitamente un reporter remoto en versiones futuras.

## Rendimiento

Performance es una prioridad.

La librería debe causar el menor impacto posible.

Evitar:

```text
polling cada pocos milisegundos
serialización profunda indiscriminada
MutationObserver sobre atributos innecesarios
captura excesiva de stack traces
clonación masiva de objetos
```

Medir los puntos sensibles.

Documentar decisiones que puedan afectar rendimiento.

## Compatibilidad

La librería debe verificar:

```ts
typeof window !== "undefined"
```

para evitar errores si accidentalmente se importa durante SSR.

Debe poder importarse en:

```text
Next.js
Nuxt
SSR environments
```

sin explotar durante el import.

Solo debe activarse en navegador.

## Testing

Utilizar Vitest.

Crear pruebas para al menos:

```text
EventBus
RiskEngine
NetworkDetector
ScriptInjectionDetector
configuración
presets
Start()
Stop()
idempotencia
historial
```

Los tests de navegador pueden utilizar:

```text
jsdom
```

cuando sea adecuado.

No simular funcionalidades que jsdom no soporte correctamente sin documentarlo.

Objetivo inicial:

```text
mínimo 80% de cobertura en Core y Detectors
```

## Build

Configurar tsup.

Generar:

```text
dist/
  index.js
  index.d.ts
```

Si es conveniente:

```text
index.mjs
index.cjs
```

pero priorizar ESM moderno.

Configurar correctamente:

```text
package.json
exports
types
files
sideEffects
```

Tree shaking debe funcionar.

## package.json

Agregar scripts similares a:

```json
{
  "scripts": {
    "dev": "tsup --watch",
    "build": "tsup",
    "test": "vitest",
    "test:coverage": "vitest run --coverage",
    "lint": "eslint .",
    "format": "prettier --write .",
    "typecheck": "tsc --noEmit"
  }
}
```

Ajustar si fuese necesario.

## Documentación

Crear:

```text
README.md
```

Debe contener:

```text
qué es BrowserGuard
qué NO es BrowserGuard
instalación
quick start
configuración
presets
monitores
eventos
ejemplos
limitaciones
seguridad
performance
roadmap
```

Ejemplo de uso:

```ts
import { BrowserGuard } from "@diforte/browser-guard";

const Guard = BrowserGuard.Start({
  Preset: "strict",

  Network: {
    AllowedOrigins: [
      window.location.origin,
      "https://api.example.com"
    ]
  },

  Dom: {
    AllowedScriptOrigins: [
      window.location.origin,
      "https://cdn.example.com"
    ]
  }
});

Guard.On("Critical", (Finding) => {
  console.error(Finding);
});
```

Explicar que BrowserGuard debe inicializarse lo antes posible.

Ejemplo Vite:

```ts
// SecurityBootstrap.ts

import { BrowserGuard } from "@diforte/browser-guard";

export const Guard = BrowserGuard.Start({
  Preset: "strict"
});
```

Luego:

```ts
// main.tsx

import "./SecurityBootstrap";

import React from "react";
import ReactDOM from "react-dom/client";

import App from "./App";

ReactDOM.createRoot(
  document.getElementById("root")!
).render(<App />);
```

## Demo

Crear dentro del repositorio:

```text
examples/
└── vite-demo/
```

Debe demostrar:

```text
fetch permitido
fetch externo sospechoso
script dinámico
CSP violation cuando sea posible
WebSocket
modificación del prototype
```

Crear botones en la demo para provocar eventos controlados.

Ejemplo:

```text
Simulate external request
Simulate dynamic script
Simulate prototype change
Simulate runtime modification
```

La demo debe servir para probar visualmente BrowserGuard.

## Roadmap

Documentar como funcionalidades futuras:

### v0.2

```text
DOM XSS detection
sinks peligrosos
innerHTML
outerHTML
document.write
eval
Function
```

### v0.3

```text
Trusted Types integration
```

### v0.4

```text
Subresource Integrity analysis
supply-chain monitoring
```

### v0.5

```text
advanced forensic timeline
```

### v0.6

```text
remote reporter
webhook reporter
SIEM integration
```

### v1.0

```text
Browser Runtime Security Platform
```

## Muy importante

NO implementar todavía:

```text
bloqueo activo de requests
bloqueo de scripts
captura de passwords
captura de tokens
captura de formularios
keylogger
clipboard monitoring
fingerprinting
telemetría remota automática
```

La versión inicial debe ser estrictamente:

```text
observe
analyze
score
report
```

## Primera etapa de implementación

No intentes construir todo simultáneamente.

Trabajar en este orden:

### Fase 1

Crear:

```text
package
TypeScript
tsup
Vitest
ESLint
estructura
tipos
configuración
```

### Fase 2

Implementar:

```text
EventBus
RiskEngine
BrowserGuard
MonitorRegistry
```

### Fase 3

Implementar:

```text
FetchMonitor
XhrMonitor
WebSocketMonitor
```

### Fase 4

Implementar:

```text
NetworkDetector
```

### Fase 5

Implementar:

```text
DomMonitor
ScriptInjectionDetector
```

### Fase 6

Implementar:

```text
CspMonitor
```

### Fase 7

Implementar:

```text
PrototypeMonitor
PrototypePollutionDetector
```

### Fase 8

Implementar:

```text
RuntimeIntegrityDetector
```

### Fase 9

Implementar:

```text
ConsoleReporter
historial
forensic mode
```

### Fase 10

Crear:

```text
README
tests
example Vite
```

Después de cada fase:

1. ejecutar typecheck;
2. ejecutar lint;
3. ejecutar tests;
4. corregir todos los errores;
5. no avanzar dejando errores pendientes.

## Criterio de calidad

Antes de considerar terminada la primera versión, verificar:

```text
pnpm build
pnpm typecheck
pnpm lint
pnpm test
```

Todos deben finalizar correctamente.

No dejar:

```text
TODO críticos
any innecesarios
console.log de debug
código muerto
imports sin utilizar
duplicación evidente
```

## Objetivo final

Al terminar quiero poder hacer:

```bash
pnpm add @diforte/browser-guard
```

y luego:

```ts
import { BrowserGuard } from "@diforte/browser-guard";

const Guard = BrowserGuard.Start({
  Preset: "strict"
});

Guard.On("Threat", (Finding) => {
  console.log(Finding);
});
```

y que BrowserGuard comience automáticamente a observar el entorno del navegador, generar eventos, analizarlos, calcular riesgo y reportar comportamientos sospechosos sin alterar el funcionamiento normal de la aplicación.

Antes de escribir código, analiza la arquitectura propuesta, identifica posibles problemas técnicos y presenta brevemente cualquier ajuste que consideres necesario.

Luego comienza la implementación siguiendo estrictamente las fases definidas.

No simplifiques la arquitectura omitiendo módulos importantes.

No agregues funcionalidades fuera del alcance inicial.

Prioriza:

```text
seguridad
estabilidad
performance
mantenibilidad
extensibilidad
developer experience
```