import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import Database from "better-sqlite3";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import Fastify, { type FastifyInstance } from "fastify";
import type Provider from "oidc-provider";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultOAuthConfig } from "./config.js";
import { ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME } from "./cookie.js";
import { createFirstPartyTokenMinter } from "./first-party.js";
import { createOAuthProvider } from "./provider.js";
import { createSigningKeyService } from "./signing-keys.js";
import { createUiSessionService, type UiSessionService } from "./ui-session.js";

type AnyDb = BetterSQLite3Database<Record<string, never>>;

interface Setup {
  app: FastifyInstance;
  provider: Provider;
  session: UiSessionService;
  close: () => Promise<void>;
}

async function setupSession(): Promise<Setup> {
  const sqlite = new Database(":memory:");
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  const db = drizzle(sqlite, { schema: {} }) as AnyDb;
  migrate(db, { migrationsFolder: resolve(import.meta.dirname, "../../drizzle") });

  const signingKeyService = createSigningKeyService({
    db: db as never,
    encryptionKey: randomBytes(32),
  });
  await signingKeyService.ensureSigningKey();

  const provider = await createOAuthProvider({
    issuer: "http://localhost/oidc",
    baseUrl: "http://localhost",
    db: db as never,
    config: { ...defaultOAuthConfig },
    signingKeyService,
  });

  const minter = createFirstPartyTokenMinter(provider, { accessTokenSeconds: 3600 });
  const session = createUiSessionService({
    provider,
    minter,
    audience: "http://localhost",
    scopes: ["mcp", "agent"],
  });

  const app = Fastify({ logger: false });

  return {
    app,
    provider,
    session,
    close: async () => {
      await app.close();
      sqlite.close();
    },
  };
}

function setCookieHeaders(res: { headers: Record<string, unknown> }): string[] {
  const raw = res.headers["set-cookie"];
  if (!raw) return [];
  return Array.isArray(raw) ? raw : [String(raw)];
}

function extract(cookies: string[], name: string): string | null {
  const hit = cookies.find((c) => c.startsWith(`${name}=`));
  if (!hit) return null;
  const kv = hit.split(";")[0]!;
  const value = kv.slice(name.length + 1);
  return value === "" ? null : decodeURIComponent(value);
}

describe("UiSessionService.tryRefresh", () => {
  let setup: Setup;

  beforeEach(async () => {
    setup = await setupSession();
  });

  afterEach(async () => {
    await setup.close();
  });

  async function mintAndCapture(accountId: string): Promise<{ access: string; refresh: string }> {
    setup.app.post("/login", async (req, reply) => {
      await setup.session.onLoginSuccess(req, reply, { accountId });
      return { ok: true };
    });
    await setup.app.ready();
    const res = await setup.app.inject({ method: "POST", url: "/login" });
    const cookies = setCookieHeaders(res);
    return {
      access: extract(cookies, ACCESS_COOKIE_NAME)!,
      refresh: extract(cookies, REFRESH_COOKIE_NAME)!,
    };
  }

  it("returns null when no refresh cookie is present", async () => {
    setup.app.post("/refresh", async (req, reply) => {
      const result = await setup.session.tryRefresh(req, reply);
      return { result };
    });
    await setup.app.ready();
    const res = await setup.app.inject({ method: "POST", url: "/refresh" });
    expect(res.json()).toEqual({ result: null });
  });

  it("rotates the cookies and returns a new access token when refresh is valid", async () => {
    const initial = await mintAndCapture("acct_refresh");

    const app2 = Fastify({ logger: false });
    try {
      app2.post("/refresh", async (req, reply) => {
        const out = await setup.session.tryRefresh(req, reply);
        return { ok: out !== null };
      });
      await app2.ready();

      const res = await app2.inject({
        method: "POST",
        url: "/refresh",
        headers: { cookie: `${REFRESH_COOKIE_NAME}=${encodeURIComponent(initial.refresh)}` },
      });
      expect(res.json()).toEqual({ ok: true });

      const cookies = setCookieHeaders(res);
      const newAccess = extract(cookies, ACCESS_COOKIE_NAME);
      const newRefresh = extract(cookies, REFRESH_COOKIE_NAME);
      expect(newAccess).toBeTruthy();
      expect(newRefresh).toBeTruthy();
      expect(newAccess).not.toBe(initial.access);
      expect(newRefresh).not.toBe(initial.refresh);

      // The new access token is a real, findable record with the
      // same accountId as the initial login.
      const rec = await setup.provider.AccessToken.find(newAccess!);
      expect(rec?.accountId).toBe("acct_refresh");
    } finally {
      await app2.close();
    }
  });

  it("rejects replay of a consumed refresh token", async () => {
    const initial = await mintAndCapture("acct_replay");

    const app2 = Fastify({ logger: false });
    try {
      app2.post("/refresh", async (req, reply) => {
        const out = await setup.session.tryRefresh(req, reply);
        return { ok: out !== null };
      });
      await app2.ready();

      const cookie = `${REFRESH_COOKIE_NAME}=${encodeURIComponent(initial.refresh)}`;

      const first = await app2.inject({
        method: "POST",
        url: "/refresh",
        headers: { cookie },
      });
      expect(first.json()).toEqual({ ok: true });

      // Replay with the same (now-consumed) refresh cookie must fail.
      const second = await app2.inject({
        method: "POST",
        url: "/refresh",
        headers: { cookie },
      });
      expect(second.json()).toEqual({ ok: false });
    } finally {
      await app2.close();
    }
  });

  it("returns null when the refresh token is expired but not yet consumed", async () => {
    // Build a setup that issues tokens with a near-zero refresh TTL by
    // re-wiring the provider with tight ttl.RefreshToken. Mint, wait
    // past expiry, then try to refresh.
    const expired = await (async () => {
      const sqlite = new Database(":memory:");
      sqlite.pragma("journal_mode = WAL");
      sqlite.pragma("foreign_keys = ON");
      const db = drizzle(sqlite, { schema: {} }) as AnyDb;
      migrate(db, { migrationsFolder: resolve(import.meta.dirname, "../../drizzle") });

      const signingKeyService = createSigningKeyService({
        db: db as never,
        encryptionKey: randomBytes(32),
      });
      await signingKeyService.ensureSigningKey();

      const provider = await createOAuthProvider({
        issuer: "http://localhost/oidc",
        baseUrl: "http://localhost",
        db: db as never,
        config: { ...defaultOAuthConfig, refreshTokenTtlSeconds: 1 },
        signingKeyService,
      });
      const minter = createFirstPartyTokenMinter(provider, { accessTokenSeconds: 3600 });
      const session = createUiSessionService({
        provider,
        minter,
        audience: "http://localhost",
        scopes: ["mcp"],
      });

      const mintApp = Fastify({ logger: false });
      mintApp.post("/login", async (req, reply) => {
        await session.onLoginSuccess(req, reply, { accountId: "acct_expired" });
        return { ok: true };
      });
      await mintApp.ready();
      const loginRes = await mintApp.inject({ method: "POST", url: "/login" });
      const refresh = extract(setCookieHeaders(loginRes), REFRESH_COOKIE_NAME)!;
      await mintApp.close();

      // Wait past the 1-second TTL.
      await new Promise((r) => setTimeout(r, 1100));

      const refreshApp = Fastify({ logger: false });
      refreshApp.post("/refresh", async (req, reply) => {
        const out = await session.tryRefresh(req, reply);
        return { ok: out !== null };
      });
      await refreshApp.ready();
      const refreshRes = await refreshApp.inject({
        method: "POST",
        url: "/refresh",
        headers: { cookie: `${REFRESH_COOKIE_NAME}=${encodeURIComponent(refresh)}` },
      });
      await refreshApp.close();
      sqlite.close();
      return refreshRes.json();
    })();

    expect(expired).toEqual({ ok: false });
  });

  it("revokes the entire grant when a consumed refresh is replayed (stolen-cookie defense)", async () => {
    const initial = await mintAndCapture("acct_replay_revoke");
    const initialAccessRec = await setup.provider.AccessToken.find(initial.access);
    const grantId = initialAccessRec?.grantId;
    expect(grantId).toBeTruthy();

    // First refresh consumes + mints a new pair.
    const app2 = Fastify({ logger: false });
    try {
      app2.post("/refresh", async (req, reply) => {
        const out = await setup.session.tryRefresh(req, reply);
        return { ok: out !== null };
      });
      await app2.ready();

      const cookie = `${REFRESH_COOKIE_NAME}=${encodeURIComponent(initial.refresh)}`;
      const firstRes = await app2.inject({ method: "POST", url: "/refresh", headers: { cookie } });
      const firstCookies = setCookieHeaders(firstRes);
      const rotatedAccess = extract(firstCookies, ACCESS_COOKIE_NAME)!;

      // Replay the original (now-consumed) refresh cookie. tryRefresh
      // must return null AND sweep the grant — so the rotated access
      // token issued by the first refresh also stops being findable.
      const replayRes = await app2.inject({
        method: "POST",
        url: "/refresh",
        headers: { cookie },
      });
      expect(replayRes.json()).toEqual({ ok: false });

      const afterReplay = await setup.provider.AccessToken.find(rotatedAccess);
      expect(afterReplay).toBeUndefined();
    } finally {
      await app2.close();
    }
  });

  it("coalesces parallel refreshes on the same cookie", async () => {
    const initial = await mintAndCapture("acct_coalesce");
    const grantIdBefore = (await setup.provider.AccessToken.find(initial.access))?.grantId;

    const app2 = Fastify({ logger: false });
    try {
      app2.post("/refresh", async (req, reply) => {
        const out = await setup.session.tryRefresh(req, reply);
        return { accessToken: out?.accessToken ?? null };
      });
      await app2.ready();

      const cookie = `${REFRESH_COOKIE_NAME}=${encodeURIComponent(initial.refresh)}`;
      // Fire N parallel refreshes.
      const results = await Promise.all(
        Array.from({ length: 5 }, () =>
          app2.inject({ method: "POST", url: "/refresh", headers: { cookie } }),
        ),
      );

      // Every caller must succeed — none of them should see the
      // "consumed" branch because the mint is coalesced.
      const accessTokens = results
        .map((r) => r.json<{ accessToken: string | null }>().accessToken)
        .filter((t): t is string => Boolean(t));
      expect(accessTokens.length).toBe(5);
      // All five callers share the same rotated access token.
      expect(new Set(accessTokens).size).toBe(1);
      // And the rotated pair lives under the same grant as the
      // original login — no Grant-row leak from the parallel storm.
      const rec = await setup.provider.AccessToken.find(accessTokens[0]!);
      expect(rec?.grantId).toBe(grantIdBefore);
    } finally {
      await app2.close();
    }
  });

  it("preserves the Grant across rotation (no row leak per refresh)", async () => {
    const initial = await mintAndCapture("acct_grant_reuse");
    const initialAccessRec = await setup.provider.AccessToken.find(initial.access);
    const grantIdBefore = initialAccessRec?.grantId;
    expect(grantIdBefore).toBeTruthy();

    const app2 = Fastify({ logger: false });
    try {
      app2.post("/refresh", async (req, reply) => {
        const out = await setup.session.tryRefresh(req, reply);
        return { accessToken: out?.accessToken ?? null };
      });
      await app2.ready();

      const res = await app2.inject({
        method: "POST",
        url: "/refresh",
        headers: { cookie: `${REFRESH_COOKIE_NAME}=${encodeURIComponent(initial.refresh)}` },
      });
      const { accessToken } = res.json<{ accessToken: string }>();
      const newRec = await setup.provider.AccessToken.find(accessToken);
      expect(newRec?.grantId).toBe(grantIdBefore);
    } finally {
      await app2.close();
    }
  });
});
