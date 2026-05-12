import crypto from "crypto";

export interface SessionPayload {
  sub: "operator";
  iat: number;
  exp: number;
}

const SESSION_DURATION_SECONDS = 60 * 60 * 12; // 12 hours

function base64urlEncode(buf: Buffer): string {
  return buf.toString("base64url");
}

function base64urlDecode(str: string): Buffer {
  return Buffer.from(str, "base64url");
}

export function signSession(
  payload: SessionPayload,
  secret: string
): string {
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = base64urlEncode(Buffer.from(payloadJson, "utf8"));

  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(payloadB64);
  const signature = base64urlEncode(hmac.digest());

  return `${payloadB64}.${signature}`;
}

export function verifySession(
  token: string,
  secret: string
): SessionPayload | null {
  const parts = token.split(".");
  if (parts.length !== 2) {
    return null;
  }

  const [payloadB64, signatureB64] = parts as [string, string];

  // Recompute expected signature
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(payloadB64);
  const expectedSig = base64urlEncode(hmac.digest());

  // Constant-time comparison of signatures
  const sigBuf = base64urlDecode(signatureB64);
  const expectedBuf = base64urlDecode(expectedSig);

  if (sigBuf.length !== expectedBuf.length) {
    // Lengths differ — still do a dummy comparison to avoid timing leaks
    // on length itself, then return null
    const dummy = Buffer.alloc(expectedBuf.length);
    crypto.timingSafeEqual(dummy, expectedBuf);
    return null;
  }

  const signaturesMatch = crypto.timingSafeEqual(sigBuf, expectedBuf);
  if (!signaturesMatch) {
    return null;
  }

  // Decode and parse payload
  let payload: unknown;
  try {
    const payloadJson = base64urlDecode(payloadB64).toString("utf8");
    payload = JSON.parse(payloadJson) as unknown;
  } catch {
    return null;
  }

  // Validate shape
  if (
    typeof payload !== "object" ||
    payload === null ||
    !("sub" in payload) ||
    !("iat" in payload) ||
    !("exp" in payload) ||
    (payload as Record<string, unknown>)["sub"] !== "operator" ||
    typeof (payload as Record<string, unknown>)["iat"] !== "number" ||
    typeof (payload as Record<string, unknown>)["exp"] !== "number"
  ) {
    return null;
  }

  const typed = payload as SessionPayload;

  // Check expiry
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typed.exp <= nowSeconds) {
    return null;
  }

  return typed;
}

export function createSessionToken(secret: string): string {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = {
    sub: "operator",
    iat: nowSeconds,
    exp: nowSeconds + SESSION_DURATION_SECONDS,
  };
  return signSession(payload, secret);
}

export async function getSession(): Promise<SessionPayload | null> {
  // Dynamic import to avoid importing next/headers at module level in tests
  const { cookies } = await import("next/headers");
  const cookieStore = await cookies();
  const token = cookieStore.get("sb_session")?.value;
  if (!token) {
    return null;
  }

  // Import env lazily to allow the module to load in test environments
  const { env } = await import("@/lib/env");
  return verifySession(token, env.SESSION_SECRET);
}
