import { createHmac, timingSafeEqual } from "node:crypto";

export interface SessionPayload {
  sub: string;
  iat: number;
  exp: number;
}

function sign(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function createSessionCookie(secret: string, ttlSeconds: number): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = {
    sub: "admin",
    iat: now,
    exp: now + ttlSeconds,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = sign(payloadB64, secret);
  return `${payloadB64}.${sig}`;
}

export function verifySessionCookie(cookie: string, secret: string): SessionPayload | null {
  const dotIdx = cookie.indexOf(".");
  if (dotIdx === -1) return null;

  const payloadB64 = cookie.slice(0, dotIdx);
  const sig = cookie.slice(dotIdx + 1);

  const expectedSig = sign(payloadB64, secret);
  if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) return null;

  try {
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString()) as SessionPayload;
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}
