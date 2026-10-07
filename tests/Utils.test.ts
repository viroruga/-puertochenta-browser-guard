import { describe, expect, it } from "vitest";
import { RedactedValue, SafeSerialize, SanitizeString } from "../src/Utils/SafeSerializer";
import {
  CallerStackFrom,
  CleanStack,
  FormatFrame,
  ParseStack,
  RaiseStackTraceLimit,
  RestoreStackTraceLimit,
} from "../src/Utils/StackTrace";
import {
  ClassifyOrigin,
  DescribeUrl,
  IsInsecureTransport,
  IsSameOrigin,
  MatchesAnyOrigin,
  NormalizeOriginPattern,
  ParseUrl,
} from "../src/Utils/UrlUtils";

describe("UrlUtils", () => {
  it("DescribeUrl elimina query, fragmento y credenciales", () => {
    expect(
      DescribeUrl("https://user:pass@api.example.com/a/b?token=1#x", "https://app.example.com"),
    ).toEqual({
      Url: "https://api.example.com/a/b",
      Origin: "https://api.example.com",
      Scheme: "https:",
      HasQuery: true,
    });
  });

  it("DescribeUrl resuelve URLs relativas y oculta esquemas no de red", () => {
    expect(DescribeUrl("/x", "https://app.example.com/page").Origin).toBe(
      "https://app.example.com",
    );
    expect(DescribeUrl("data:text/javascript,alert(1)", "https://app.example.com")).toMatchObject({
      Url: "data:[redacted]",
      Origin: null,
      Scheme: "data:",
    });
    expect(DescribeUrl("http://[bad", "https://app.example.com").Url).toBe("[invalid-url]");
  });

  it("NormalizeOriginPattern", () => {
    expect(NormalizeOriginPattern("https://*.Example.com/path")).toBe("https://*.example.com");
    expect(NormalizeOriginPattern(" https://a.example.com:8443/x ")).toBe(
      "https://a.example.com:8443",
    );
    expect(NormalizeOriginPattern("   ")).toBeNull();
    expect(NormalizeOriginPattern("mailto:x@example.com")).toBeNull();
  });

  it("MatchesAnyOrigin soporta comodines de subdominio y equivalencia ws ↔ http", () => {
    expect(MatchesAnyOrigin("https://a.b.example.com", ["https://*.example.com"])).toBe(true);
    expect(MatchesAnyOrigin("https://example.com", ["https://*.example.com"])).toBe(false);
    expect(MatchesAnyOrigin("https://evilexample.com", ["https://*.example.com"])).toBe(false);
    expect(MatchesAnyOrigin("http://a.example.com", ["https://*.example.com"])).toBe(false);
    expect(MatchesAnyOrigin("wss://api.example.com", ["https://api.example.com"])).toBe(true);
    expect(MatchesAnyOrigin("ws://api.example.com", ["http://api.example.com"])).toBe(true);
  });

  it("ClassifyOrigin prioriza bloqueados", () => {
    const page = "https://app.example.com";
    expect(ClassifyOrigin(null, page, [], [])).toBe("non-network");
    expect(ClassifyOrigin(page, page, [], [page])).toBe("blocked");
    expect(ClassifyOrigin(page, page, [], [])).toBe("same-origin");
    expect(ClassifyOrigin("https://x.example", page, ["https://x.example"], [])).toBe("allowed");
    expect(ClassifyOrigin("https://y.example", page, [], [])).toBe("unknown");
  });

  it("IsSameOrigin e IsInsecureTransport", () => {
    expect(IsSameOrigin("wss://app.example.com", "https://app.example.com")).toBe(true);
    expect(IsSameOrigin("https://app.example.com:444", "https://app.example.com")).toBe(false);
    const url = ParseUrl("ws://x.example");
    expect(url && IsInsecureTransport(url, "https:")).toBe(true);
    expect(url && IsInsecureTransport(url, "http:")).toBe(false);
  });
});

describe("SafeSerializer", () => {
  it("censura claves sensibles sin afectar claves similares", () => {
    expect(
      SafeSerialize({
        password: "x",
        Authorization: "Bearer y",
        cookie: "a=b",
        apiKey: "k",
        sessionId: "s",
        cardNumber: "4111",
        author: "Ana",
        span: 3,
      }),
    ).toEqual({
      password: RedactedValue,
      Authorization: RedactedValue,
      cookie: RedactedValue,
      apiKey: RedactedValue,
      sessionId: RedactedValue,
      cardNumber: RedactedValue,
      author: "Ana",
      span: 3,
    });
  });

  it("censura JWT, Bearer y números de tarjeta dentro de strings", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const text = SanitizeString(`token ${jwt} Bearer abc.def card 4111 1111 1111 1111`);
    expect(text).not.toContain(jwt);
    expect(text).not.toContain("abc.def");
    expect(text).not.toContain("4111 1111");
  });

  it("trunca strings largos", () => {
    expect(SanitizeString("a".repeat(500), 10)).toBe(`${"a".repeat(10)}…`);
  });

  it("maneja ciclos, profundidad, funciones, símbolos, bigint y getters hostiles", () => {
    const cyclic: Record<string, unknown> = { name: "root" };
    cyclic.self = cyclic;
    const hostile = Object.defineProperty({}, "boom", {
      enumerable: true,
      get() {
        throw new Error("hostile");
      },
    });
    const result = SafeSerialize(
      {
        cyclic,
        deep: { a: { b: { c: { d: 1 } } } },
        list: [{ x: [1] }],
        fn: function named() {},
        sym: Symbol("s"),
        big: 10n,
        nothing: null,
        missing: undefined,
        hostile,
      },
      { MaxDepth: 3 },
    );
    expect(result).toMatchObject({
      cyclic: { name: "root", self: "[circular]" },
      deep: { a: { b: "[object]" } },
      list: [{ x: "[array]" }],
      fn: "[function named]",
      sym: "Symbol(s)",
      big: "10",
      nothing: null,
      hostile: { boom: "[unreadable]" },
    });
  });

  it("limita la cantidad de claves y elementos", () => {
    const many = Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`k${i}`, i]));
    expect(Object.keys(SafeSerialize(many, { MaxKeys: 5 }) as object)).toHaveLength(5);
    expect(
      SafeSerialize(
        Array.from({ length: 50 }, (_, i) => i),
        { MaxKeys: 3 },
      ),
    ).toEqual([0, 1, 2]);
  });

  it("objetos cuyo listado de claves falla", () => {
    const proxy = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error("no keys");
        },
      },
    );
    expect(SafeSerialize(proxy)).toBe("[unserializable]");
  });
});

describe("StackTrace", () => {
  const V8Stack = [
    "Error",
    "    at CaptureStack (http://localhost:5173/node_modules/@puertochenta/browser-guard/dist/index.js:10:5)",
    "    at Object.apply (http://localhost:5173/node_modules/@puertochenta/browser-guard/dist/index.js:20:7)",
    "    at submitPayment (http://localhost:5173/src/Payment.ts?t=123:82:5)",
    "    at async onClick (http://localhost:5173/src/Checkout.tsx:143:9)",
    "    at http://localhost:5173/src/main.ts:5:1",
    "    at new Promise (<anonymous>)",
  ].join("\n");

  const GeckoStack = [
    "CaptureStack@http://localhost:5173/@fs/D:/Projects/browser-guard/src/Utils/StackTrace.ts:10:5",
    "submitPayment@http://localhost:5173/src/Payment.ts:82:5",
    "@http://localhost:5173/src/main.ts:5:1",
  ].join("\n");

  it("parsea frames V8 y Gecko", () => {
    expect(ParseStack(V8Stack)).toHaveLength(5);
    expect(ParseStack(GeckoStack)[1]).toEqual({
      FunctionName: "submitPayment",
      File: "http://localhost:5173/src/Payment.ts",
      Line: 82,
      Column: 5,
    });
  });

  it("elimina frames internos y simplifica rutas", () => {
    expect(CleanStack(V8Stack, 10)).toBe(
      ["submitPayment() Payment.ts:82:5", "onClick() Checkout.tsx:143:9", "main.ts:5:1"].join("\n"),
    );
    expect(CleanStack(GeckoStack, 10)).toBe(
      ["submitPayment() Payment.ts:82:5", "main.ts:5:1"].join("\n"),
    );
  });

  it("respeta el máximo de frames y retorna undefined si no queda ninguno", () => {
    expect(CleanStack(V8Stack, 1)).toBe("submitPayment() Payment.ts:82:5");
    expect(
      CleanStack(
        "Error\n    at x (http://h/node_modules/@puertochenta/browser-guard/dist/index.js:1:1)",
        5,
      ),
    ).toBeUndefined();
  });

  it("FormatFrame sin nombre de función", () => {
    expect(
      FormatFrame({ FunctionName: null, File: "C:\\app\\src\\a.ts", Line: 1, Column: 2 }),
    ).toBe("a.ts:1:2");
  });

  it("descarta frames por posición aunque la librería comparta archivo con la app", () => {
    // Bundle de producción: trampa interna y código de la app en el mismo archivo.
    const bundled = [
      "Error",
      "    at Object.apply (https://shop.example.com/assets/index-a1b2.js:1:5000)",
      "    at submitPayment (https://shop.example.com/assets/index-a1b2.js:1:900)",
      "    at onClick (https://shop.example.com/assets/index-a1b2.js:1:1200)",
    ].join("\n");
    expect(CleanStack(bundled, 10, 1)).toBe(
      ["submitPayment() index-a1b2.js:1:900", "onClick() index-a1b2.js:1:1200"].join("\n"),
    );
  });

  it("CallerStackFrom omite la función donde se creó el Error", () => {
    function Trap(): Error {
      return new Error();
    }
    function CallingCode(): Error {
      return Trap();
    }
    const stack = CallerStackFrom(CallingCode(), 5);
    expect(stack?.split("\n")[0]).toContain("CallingCode");
    expect(stack).not.toContain("Trap");
    expect(CallerStackFrom({ stack: undefined } as Error, 5)).toBeUndefined();
  });

  it("RaiseStackTraceLimit solo eleva el límite y RestoreStackTraceLimit lo repone", () => {
    const errorConstructor = Error as ErrorConstructor & { stackTraceLimit: number };
    const before = errorConstructor.stackTraceLimit;
    const previous = RaiseStackTraceLimit(before + 5);
    expect(errorConstructor.stackTraceLimit).toBe(before + 5);
    RestoreStackTraceLimit(previous);
    expect(errorConstructor.stackTraceLimit).toBe(before);

    RaiseStackTraceLimit(1);
    expect(errorConstructor.stackTraceLimit).toBe(before);
    RestoreStackTraceLimit(undefined);
    expect(errorConstructor.stackTraceLimit).toBe(before);
  });
});
