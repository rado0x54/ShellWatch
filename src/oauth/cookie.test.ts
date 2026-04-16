import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ACCESS_COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  clearFirstPartyCookies,
  setFirstPartyCookies,
} from "./cookie.js";
import type { MintedFirstPartyTokens } from "./first-party.js";

function fakeTokens(overrides: Partial<MintedFirstPartyTokens> = {}): MintedFirstPartyTokens {
  const now = Date.now();
  return {
    accessToken: "opaque-access",
    accessTokenExpiresAt: new Date(now + 60 * 60 * 1000),
    refreshToken: "opaque-refresh",
    refreshTokenExpiresAt: new Date(now + 30 * 24 * 60 * 60 * 1000),
    ...overrides,
  };
}

function setCookieHeaders(res: { headers: Record<string, unknown> }): string[] {
  const raw = res.headers["set-cookie"];
  if (!raw) return [];
  return Array.isArray(raw) ? raw : [String(raw)];
}

describe("setFirstPartyCookies / clearFirstPartyCookies", () => {
  let app: FastifyInstance;

  beforeEach(() => {
    app = Fastify({ logger: false });
  });

  afterEach(async () => {
    await app.close();
  });

  it("writes HttpOnly sw_session and sw_refresh cookies with SameSite=Strict", async () => {
    app.post("/login", async (req, reply) => {
      setFirstPartyCookies(req, reply, { tokens: fakeTokens() });
      return { ok: true };
    });
    await app.ready();

    const res = await app.inject({ method: "POST", url: "/login" });
    expect(res.statusCode).toBe(200);

    const cookies = setCookieHeaders(res);
    const access = cookies.find((c) => c.startsWith(`${ACCESS_COOKIE_NAME}=`));
    const refresh = cookies.find((c) => c.startsWith(`${REFRESH_COOKIE_NAME}=`));
    expect(access).toBeTruthy();
    expect(refresh).toBeTruthy();

    expect(access!).toContain("HttpOnly");
    expect(access!).toContain("SameSite=Strict");
    expect(access!).toContain("Path=/");
    expect(access!).toMatch(/Max-Age=\d+/);
    expect(refresh!).toContain("HttpOnly");
    expect(refresh!).toContain("SameSite=Strict");
    expect(refresh!).toContain("Path=/");
    expect(refresh!).toMatch(/Max-Age=\d+/);
  });

  it("omits the Secure attribute on plain http (localhost dev)", async () => {
    app.post("/login", async (req, reply) => {
      setFirstPartyCookies(req, reply, { tokens: fakeTokens() });
      return { ok: true };
    });
    await app.ready();

    const res = await app.inject({ method: "POST", url: "/login" });
    const cookies = setCookieHeaders(res);
    for (const c of cookies) {
      expect(c).not.toContain("Secure");
    }
  });

  it("adds Secure when Fastify's trustProxy-aware request.protocol is https", async () => {
    // Spin up a fresh Fastify with `trustProxy: true` — under that
    // config Fastify resolves `request.protocol` from
    // `X-Forwarded-Proto` (otherwise it's always the raw TCP protocol).
    // This is the pathway production deployments behind a reverse proxy
    // take; injecting `X-Forwarded-Proto` without configuring
    // trustProxy would bypass the guard that makes the header
    // trustworthy in the first place.
    const trustedApp = Fastify({ logger: false, trustProxy: true });
    trustedApp.post("/login", async (req, reply) => {
      setFirstPartyCookies(req, reply, { tokens: fakeTokens() });
      return { ok: true };
    });
    await trustedApp.ready();
    try {
      const res = await trustedApp.inject({
        method: "POST",
        url: "/login",
        headers: { "x-forwarded-proto": "https" },
      });
      const cookies = setCookieHeaders(res);
      expect(cookies.length).toBeGreaterThan(0);
      for (const c of cookies) {
        expect(c).toContain("Secure");
      }
    } finally {
      await trustedApp.close();
    }
  });

  it("does NOT add Secure when X-Forwarded-Proto is injected but trustProxy is off", async () => {
    app.post("/login", async (req, reply) => {
      setFirstPartyCookies(req, reply, { tokens: fakeTokens() });
      return { ok: true };
    });
    await app.ready();

    const res = await app.inject({
      method: "POST",
      url: "/login",
      headers: { "x-forwarded-proto": "https" },
    });
    const cookies = setCookieHeaders(res);
    for (const c of cookies) {
      expect(c).not.toContain("Secure");
    }
  });

  it("urlencodes token values so stray characters can't break cookie parsing", async () => {
    app.post("/login", async (req, reply) => {
      setFirstPartyCookies(req, reply, {
        tokens: fakeTokens({ accessToken: "has;semi=sign" }),
      });
      return { ok: true };
    });
    await app.ready();

    const res = await app.inject({ method: "POST", url: "/login" });
    const access = setCookieHeaders(res).find((c) => c.startsWith(`${ACCESS_COOKIE_NAME}=`));
    expect(access).toContain("has%3Bsemi%3Dsign");
  });

  it("derives Max-Age from token expiry", async () => {
    const now = Date.now();
    const accessTtlMs = 10 * 60 * 1000; // 10 minutes
    const refreshTtlMs = 2 * 24 * 60 * 60 * 1000; // 2 days
    app.post("/login", async (req, reply) => {
      setFirstPartyCookies(req, reply, {
        tokens: fakeTokens({
          accessTokenExpiresAt: new Date(now + accessTtlMs),
          refreshTokenExpiresAt: new Date(now + refreshTtlMs),
        }),
      });
      return { ok: true };
    });
    await app.ready();

    const res = await app.inject({ method: "POST", url: "/login" });
    const cookies = setCookieHeaders(res);
    const access = cookies.find((c) => c.startsWith(`${ACCESS_COOKIE_NAME}=`))!;
    const refresh = cookies.find((c) => c.startsWith(`${REFRESH_COOKIE_NAME}=`))!;

    const accessMaxAge = Number(access.match(/Max-Age=(\d+)/)?.[1]);
    const refreshMaxAge = Number(refresh.match(/Max-Age=(\d+)/)?.[1]);
    expect(accessMaxAge).toBeGreaterThan(0);
    expect(accessMaxAge).toBeLessThanOrEqual(Math.ceil(accessTtlMs / 1000));
    expect(refreshMaxAge).toBeGreaterThan(Math.ceil(accessTtlMs / 1000));
    expect(refreshMaxAge).toBeLessThanOrEqual(Math.ceil(refreshTtlMs / 1000));
  });

  it("clearFirstPartyCookies writes Max-Age=0 for both names", async () => {
    app.post("/logout", async (req, reply) => {
      clearFirstPartyCookies(req, reply);
      return { ok: true };
    });
    await app.ready();

    const res = await app.inject({ method: "POST", url: "/logout" });
    const cookies = setCookieHeaders(res);
    const access = cookies.find((c) => c.startsWith(`${ACCESS_COOKIE_NAME}=;`));
    const refresh = cookies.find((c) => c.startsWith(`${REFRESH_COOKIE_NAME}=;`));
    expect(access).toContain("Max-Age=0");
    expect(refresh).toContain("Max-Age=0");
    expect(access).toContain("HttpOnly");
    expect(refresh).toContain("HttpOnly");
  });

  it("is purely a reply-side operation (does not mutate the request)", async () => {
    let captured: FastifyRequest | null = null;
    app.post("/login", async (req, reply) => {
      captured = req;
      setFirstPartyCookies(req, reply, { tokens: fakeTokens() });
      return { ok: true };
    });
    await app.ready();

    await app.inject({ method: "POST", url: "/login" });
    expect(captured!.headers.cookie).toBeUndefined();
  });
});
