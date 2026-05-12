import { describe, it, expect } from "vitest";
import { signSession, verifySession } from "../../src/lib/auth/session";
import type { SessionPayload } from "../../src/lib/auth/session";

const SECRET = "a".repeat(32); // 32-char secret for tests

function makePayload(overrides: Partial<SessionPayload> = {}): SessionPayload {
  const nowSeconds = Math.floor(Date.now() / 1000);
  return {
    sub: "operator",
    iat: nowSeconds,
    exp: nowSeconds + 3600,
    ...overrides,
  };
}

describe("signSession / verifySession roundtrip", () => {
  it("signs and verifies a valid payload", () => {
    const payload = makePayload();
    const token = signSession(payload, SECRET);
    const result = verifySession(token, SECRET);

    expect(result).not.toBeNull();
    expect(result?.sub).toBe("operator");
    expect(result?.iat).toBe(payload.iat);
    expect(result?.exp).toBe(payload.exp);
  });

  it("returns null for a tampered payload", () => {
    const payload = makePayload();
    const token = signSession(payload, SECRET);

    // Tamper with the payload portion
    const [payloadB64, sig] = token.split(".");
    const tamperedPayload = Buffer.from(
      Buffer.from(payloadB64 ?? "", "base64url").toString("utf8").replace(
        "operator",
        "attacker"
      )
    ).toString("base64url");
    const tampered = `${tamperedPayload}.${sig}`;

    const result = verifySession(tampered, SECRET);
    expect(result).toBeNull();
  });

  it("returns null for a tampered signature", () => {
    const payload = makePayload();
    const token = signSession(payload, SECRET);

    const [payloadB64] = token.split(".");
    const tampered = `${payloadB64}.invalidsignature`;

    const result = verifySession(tampered, SECRET);
    expect(result).toBeNull();
  });

  it("returns null for a wrong secret", () => {
    const payload = makePayload();
    const token = signSession(payload, SECRET);
    const result = verifySession(token, "b".repeat(32));
    expect(result).toBeNull();
  });

  it("returns null for an expired token", () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const payload = makePayload({
      iat: nowSeconds - 7200,
      exp: nowSeconds - 3600, // expired 1 hour ago
    });
    const token = signSession(payload, SECRET);
    const result = verifySession(token, SECRET);
    expect(result).toBeNull();
  });

  it("returns null for a malformed token (no dot separator)", () => {
    const result = verifySession("notavalidtoken", SECRET);
    expect(result).toBeNull();
  });

  it("returns null for an empty string", () => {
    const result = verifySession("", SECRET);
    expect(result).toBeNull();
  });

  it("returns null for a token with extra dots", () => {
    const result = verifySession("a.b.c", SECRET);
    expect(result).toBeNull();
  });

  it("produces different tokens for different secrets", () => {
    const payload = makePayload();
    const token1 = signSession(payload, "a".repeat(32));
    const token2 = signSession(payload, "b".repeat(32));
    expect(token1).not.toBe(token2);
  });
});
