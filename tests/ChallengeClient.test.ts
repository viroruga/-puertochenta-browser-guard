import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserGuard } from "../src/BrowserGuard";
import { ResolveAntiScrapingConfig } from "../src/Config/ResolveAntiScrapingConfig";
import { AntiScraping } from "../src/Plugins/AntiScrapingPlugin";
import { ChallengeClient } from "../src/Protection/ChallengeClient";
import { CreateChallenge, VerifyRequest } from "../src/Server/Index";
import { ResetGuard } from "./Helpers";

const Secret = "test-secret-with-at-least-32-characters!!";
const Page = "https://app.example.com/";

function JsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function FakeWindow(fetchMock: unknown): Window & typeof globalThis {
  return { fetch: fetchMock, setTimeout, clearTimeout } as unknown as Window & typeof globalThis;
}

async function IssueFor(url: string): Promise<Response> {
  const sid = new URL(url).searchParams.get("sid");
  return JsonResponse(await CreateChallenge({ Secret, Difficulty: 8, SessionId: sid }));
}

describe("ResolveAntiScrapingConfig: Challenge", () => {
  it("valida el endpoint con las reglas de seguridad", () => {
    expect(
      ResolveAntiScrapingConfig({ Challenge: { Endpoint: "/api/challenge" } }, Page)?.Challenge,
    ).toEqual({ Endpoint: "https://app.example.com/api/challenge" });
    expect(
      ResolveAntiScrapingConfig({ Challenge: { Endpoint: "http://evil.example/c" } }, Page)
        ?.Challenge,
    ).toBeNull();
    expect(ResolveAntiScrapingConfig({ Challenge: "nope" }, Page)?.Challenge).toBeNull();
  });
});

describe("ChallengeClient", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("obtiene el desafío con la sesión, lo resuelve y produce una prueba verificable", async () => {
    const fetchMock = vi.fn(IssueFor);
    const client = new ChallengeClient(
      "https://app.example.com/api/challenge",
      "session-1",
      FakeWindow(fetchMock),
    );
    expect(client.GetState()).toBe("pending");
    client.Start();
    await vi.waitFor(() => {
      expect(client.GetState()).toBe("ready");
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://app.example.com/api/challenge?sid=session-1",
      expect.objectContaining({ method: "GET", cache: "no-store" }),
    );
    const header = `human; score=0; sid=session-1; proof=${client.GetProof() ?? ""}`;
    const result = await VerifyRequest({ "x-browserguard-verdict": header }, { Secret });
    expect(result.Decision).toBe("allow");
    client.Dispose();
  });

  it("si el endpoint falla queda en failed y reintenta; Dispose cancela", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn((_url: string) => Promise.resolve(JsonResponse({ error: true }, 500)));
    const client = new ChallengeClient("https://app.example.com/c?x=1", "s", FakeWindow(fetchMock));
    client.Start();
    await vi.waitFor(() => {
      expect(client.GetState()).toBe("failed");
    });
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://app.example.com/c?x=1&sid=s");
    await vi.advanceTimersByTimeAsync(5_000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    client.Dispose();
    await vi.advanceTimersByTimeAsync(600_000);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("respuestas inválidas y ausencia de fetch se tratan como fallo", async () => {
    const invalid = new ChallengeClient(
      "https://a.example/c",
      "s",
      FakeWindow(vi.fn(() => Promise.resolve(JsonResponse({ Challenge: 1 })))),
    );
    invalid.Start();
    await vi.waitFor(() => {
      expect(invalid.GetState()).toBe("failed");
    });
    invalid.Dispose();

    const none = new ChallengeClient("https://a.example/c", "s", FakeWindow(undefined));
    none.Start();
    await vi.waitFor(() => {
      expect(none.GetState()).toBe("failed");
    });
    none.Dispose();
  });
});

describe("Desafío integrado en el plugin", () => {
  afterEach(() => {
    ResetGuard();
  });

  const Quiet = {
    Console: "silent",
    Monitors: {
      Xhr: false,
      WebSocket: false,
      Dom: false,
      Csp: false,
      Prototype: false,
      Runtime: false,
      Sinks: false,
      Channels: false,
      Realms: false,
    },
  } as const;

  it("la prueba viaja en el header de veredicto y el servidor la acepta", async () => {
    const original = vi.fn(async (input: string, init?: RequestInit) => {
      if (input.includes("/api/challenge")) {
        return IssueFor(input);
      }
      const verdict = new Headers(init?.headers).get("X-BrowserGuard-Verdict");
      const result = await VerifyRequest(
        { "x-browserguard-verdict": verdict ?? undefined },
        { Secret },
      );
      return JsonResponse({ Decision: result.Decision });
    });
    window.fetch = original as unknown as typeof window.fetch;

    const guard = BrowserGuard.Start({
      ...Quiet,
      Plugins: [
        AntiScraping({
          Signals: { Environment: false },
          Challenge: { Endpoint: "/api/challenge" },
        }),
      ],
    });
    await vi.waitFor(() => {
      expect(guard.GetBotAssessment()?.Proof).toBe("ready");
    });
    const response = await window.fetch("/api/catalog");
    expect(await response.json()).toEqual({ Decision: "allow" });
    // La solicitud del desafío no pasó por el interceptor (fetch original capturado).
    expect(guard.GetReport().Findings).toEqual([]);
  });

  it("sin desafío configurado, Proof es disabled", () => {
    const guard = BrowserGuard.Start({
      ...Quiet,
      Plugins: [AntiScraping({ Signals: { Environment: false } })],
    });
    expect(guard.GetBotAssessment()?.Proof).toBe("disabled");
  });
});
