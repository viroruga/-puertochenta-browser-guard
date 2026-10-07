// @vitest-environment node
import { describe, expect, it } from "vitest";
import {
  CreateChallenge,
  ParseVerdictHeader,
  VerifyProof,
  VerifyRequest,
} from "../src/Server/Index";
import {
  CheckWork,
  FromBase64Url,
  LeadingZeroBits,
  SolveWork,
  ToBase64Url,
} from "../src/Utils/ProofOfWork";

const Secret = "test-secret-with-at-least-32-characters!!";
const Now = 1_760_000_000_000;

async function Solve(challenge: string, difficulty: number): Promise<string> {
  const nonce = await SolveWork(challenge, difficulty);
  return `${challenge}~${String(nonce)}`;
}

describe("ProofOfWork", () => {
  it("cuenta bits en cero al inicio", () => {
    expect(LeadingZeroBits(new Uint8Array([0, 0, 0x0f]))).toBe(20);
    expect(LeadingZeroBits(new Uint8Array([0x80]))).toBe(0);
    expect(LeadingZeroBits(new Uint8Array([0, 0]))).toBe(16);
  });

  it("resuelve y verifica; base64url ida y vuelta", async () => {
    const nonce = await SolveWork("abc", 8);
    expect(nonce).not.toBeNull();
    expect(await CheckWork("abc", nonce ?? -1, 8)).toBe(true);
    expect(await CheckWork("abc", -1, 8)).toBe(false);
    expect(await SolveWork("abc", 8, { aborted: true })).toBeNull();
    const bytes = new Uint8Array([0, 250, 251, 255, 62, 63]);
    expect(FromBase64Url(ToBase64Url(bytes))).toEqual(bytes);
    expect(FromBase64Url("not valid!")).toBeNull();
    expect(FromBase64Url("a")).toBeNull();
  });
});

describe("CreateChallenge / VerifyProof", () => {
  it("una prueba resuelta es válida", async () => {
    const issued = await CreateChallenge({ Secret, Difficulty: 8, SessionId: "s1", Now });
    expect(issued).toMatchObject({
      Difficulty: 8,
      ExpiresAt: Math.floor(Now / 1000) * 1000 + 600_000,
    });
    const proof = await Solve(issued.Challenge, 8);
    expect(await VerifyProof(proof, { Secret, SessionId: "s1", Now })).toEqual({
      Status: "valid",
      ExpiresAt: issued.ExpiresAt,
    });
  });

  it("detecta prueba ausente, mal formada, firma inválida, vencida y de otra sesión", async () => {
    const issued = await CreateChallenge({ Secret, Difficulty: 8, SessionId: "s1", Now });
    const proof = await Solve(issued.Challenge, 8);
    const statuses = await Promise.all([
      VerifyProof(undefined, { Secret, Now }),
      VerifyProof("garbage", { Secret, Now }),
      VerifyProof(`${issued.Challenge}~abc`, { Secret, Now }),
      VerifyProof("a.b.c~1", { Secret, Now }),
      VerifyProof(proof, { Secret: `${Secret}-other`, SessionId: "s1", Now }),
      VerifyProof(proof, { Secret, SessionId: "s1", Now: issued.ExpiresAt }),
      VerifyProof(proof, { Secret, SessionId: "s2", Now }),
    ]);
    expect(statuses.map((result) => result.Status)).toEqual([
      "missing",
      "malformed",
      "malformed",
      "malformed",
      "invalid-signature",
      "expired",
      "session-mismatch",
    ]);
  });

  it("una solución incorrecta no pasa (sin trabajo)", async () => {
    const issued = await CreateChallenge({ Secret, Difficulty: 20, Now });
    // Con 20 bits, una solución arbitraria es válida con probabilidad 1/2^20.
    const result = await VerifyProof(`${issued.Challenge}~0`, { Secret, Now });
    expect(result.Status).toBe("invalid-work");
  });

  it("un payload alterado invalida la firma", async () => {
    const issued = await CreateChallenge({ Secret, Difficulty: 8, Now });
    const [, signature] = issued.Challenge.split(".");
    const forged = ToBase64Url(
      new TextEncoder().encode(JSON.stringify({ v: 1, n: "x", iat: 0, exp: 9_999_999_999, d: 8 })),
    );
    const proof = await Solve(`${forged}.${signature ?? ""}`, 8);
    expect((await VerifyProof(proof, { Secret, Now })).Status).toBe("invalid-signature");
  });

  it("exige un secreto de al menos 32 caracteres y acota la dificultad", async () => {
    await expect(CreateChallenge({ Secret: "short" })).rejects.toThrow("at least 32");
    expect((await CreateChallenge({ Secret, Difficulty: 99 })).Difficulty).toBe(24);
    expect((await CreateChallenge({ Secret, Difficulty: 1 })).Difficulty).toBe(8);
  });
});

describe("VerifyRequest", () => {
  async function Header(verdict: string, sessionId = "s1"): Promise<string> {
    const issued = await CreateChallenge({ Secret, Difficulty: 8, SessionId: sessionId, Now });
    return `${verdict}; score=10; sid=${sessionId}; proof=${await Solve(issued.Challenge, 8)}`;
  }

  it("decide allow / challenge / deny", async () => {
    const human = await VerifyRequest(
      { "x-browserguard-verdict": await Header("human") },
      { Secret, Now },
    );
    expect(human).toMatchObject({
      Decision: "allow",
      Proof: { Status: "valid" },
      Verdict: { Verdict: "human", SessionId: "s1" },
    });

    const suspicious = await VerifyRequest(
      new Headers({ "X-BrowserGuard-Verdict": await Header("suspicious") }),
      { Secret, Now },
    );
    expect(suspicious.Decision).toBe("challenge");

    const bot = await VerifyRequest(
      { "X-BrowserGuard-Verdict": await Header("bot") },
      { Secret, Now },
    );
    expect(bot.Decision).toBe("deny");

    // curl / Scrapy: sin header.
    const curl = await VerifyRequest({}, { Secret, Now });
    expect(curl).toMatchObject({ Decision: "deny", Proof: { Status: "missing" }, Verdict: null });

    // Header falsificado sin prueba.
    const forged = await VerifyRequest(
      { "x-browserguard-verdict": "human; score=0; sid=s1" },
      { Secret, Now },
    );
    expect(forged).toMatchObject({ Decision: "deny", Proof: { Status: "missing" } });

    const expired = await VerifyRequest(
      { "x-browserguard-verdict": await Header("human") },
      { Secret, Now: Now + 601_000 },
    );
    expect(expired.Decision).toBe("challenge");

    const array = await VerifyRequest(
      { "x-browserguard-verdict": [await Header("human")] },
      { Secret, Now },
    );
    expect(array.Decision).toBe("allow");
  });

  it("ParseVerdictHeader tolera entradas inválidas", () => {
    expect(ParseVerdictHeader("evil; score=5")).toBeNull();
    expect(ParseVerdictHeader(null)).toBeNull();
    expect(ParseVerdictHeader("x".repeat(5000))).toBeNull();
    expect(ParseVerdictHeader("human; score=abc")).toEqual({
      Verdict: "human",
      Score: 0,
      SessionId: null,
      Proof: null,
    });
    expect(ParseVerdictHeader("bot; score=500")?.Score).toBe(100);
  });
});
