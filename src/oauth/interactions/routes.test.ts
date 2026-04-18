import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import Database from "better-sqlite3";
import Fastify, { type FastifyInstance } from "fastify";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import type Provider from "oidc-provider";
import { afterEach, describe, expect, it } from "vitest";
import type { Config } from "../../config/index.js";
import { StubAccountRepository } from "../../db/index.js";
import { defaultOAuthConfig } from "../config.js";
import { registerOAuth } from "../register.js";

type AnyDb = BetterSQLite3Database<Record<string, never>>;

const testSecurity: Config["security"] = {
  rpId: "localhost",
  allowedNetworks: ["127.0.0.1/32"],
  sessionTtlSeconds: 86400,
  selfRegistrationEnabled: false,
  rateLimit: {
    selfRegister: { max: 5, windowMinutes: 15 },
    passkeyRegister: { max: 10, windowMinutes: 15 },
    loginOptions: { max: 20, windowMinutes: 15 },
    loginVerify: { max: 10, windowMinutes: 15 },
  },
  trustedWebauthnOrigins: ["http://localhost"],
};

interface Setup {
  app: FastifyInstance;
  baseUrl: string;
  provider: Provider;
  close: () => Promise<void>;
}

async function setup(configOverrides: Partial<typeof defaultOAuthConfig> = {}): Promise<Setup> {
  const sqlite = new Database(":memory:");
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  const db = drizzle(sqlite, { schema: {} }) as AnyDb;
  migrate(db, { migrationsFolder: resolve(import.meta.dirname, "../../../drizzle") });

  const { createServer } = await import("node:net");
  const probe = createServer();
  await new Promise<void>((res) => probe.listen(0, "127.0.0.1", res));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((res) => probe.close(() => res()));

  const baseUrl = `http://127.0.0.1:${port}`;
  const app = Fastify({ logger: false });
  const result = await registerOAuth({
    app,
    db: db as never,
    config: { ...defaultOAuthConfig, ...configOverrides },
    baseUrl,
    sessionSecret: randomBytes(32).toString("hex"),
    accountRepo: new StubAccountRepository(),
    security: testSecurity,
  });
  if (!result) throw new Error("registerOAuth returned null");
  await app.listen({ port, host: "127.0.0.1" });

  return {
    app,
    baseUrl,
    provider: result.provider,
    close: async () => {
      await app.close();
      sqlite.close();
    },
  };
}

describe("DCR (Dynamic Client Registration)", () => {
  let s: Setup;
  afterEach(async () => {
    if (s) await s.close();
  });

  it("accepts grant_types containing refresh_token (RFC 7591 compat)", async () => {
    s = await setup();
    const res = await fetch(`${s.baseUrl}/oidc/reg`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "MCP Inspector",
        redirect_uris: ["http://127.0.0.1:6274/oauth/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.client_id).toBeTruthy();
    // refresh_token is silently stripped — panva only stores the
    // grant types it recognises at the client level.
    expect(body.grant_types).toEqual(["authorization_code"]);
  });

  it("registers a public client and returns client_id", async () => {
    s = await setup();
    const res = await fetch(`${s.baseUrl}/oidc/reg`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Test MCP Client",
        redirect_uris: ["http://127.0.0.1:54321/callback"],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        // id_token_signed_response_alg intentionally omitted —
        // clientDefaults in provider.ts should fill in "EdDSA" so DCR
        // clients don't need to know our key type.
      }),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.client_id).toBeTruthy();
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.redirect_uris).toEqual(["http://127.0.0.1:54321/callback"]);

    // The registered client is resolvable via the Provider.
    const client = await s.provider.Client.find(String(body.client_id));
    expect(client).toBeDefined();
    expect(client?.clientName).toBe("Test MCP Client");
  });

  it("enforces the per-IP rate limit on /oidc/reg", async () => {
    s = await setup({ registrationRateLimitPerMinute: 3 });

    const register = () =>
      fetch(`${s.baseUrl}/oidc/reg`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "Rate test",
          redirect_uris: ["http://127.0.0.1/callback"],
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
          id_token_signed_response_alg: "EdDSA",
        }),
      });

    // First three succeed.
    for (let i = 0; i < 3; i++) {
      const ok = await register();
      expect(ok.status).toBe(201);
    }
    // Fourth is rejected with 429 + Retry-After.
    const limited = await register();
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toMatch(/^\d+$/);
    const body = (await limited.json()) as Record<string, unknown>;
    expect(body.error).toBe("too_many_requests");
  });

  it("omits the registration endpoint + rate limit when DCR is disabled", async () => {
    s = await setup({ dynamicClientRegistration: "disabled" });
    const meta = await fetch(`${s.baseUrl}/oidc/.well-known/openid-configuration`);
    const metaBody = (await meta.json()) as Record<string, unknown>;
    expect(metaBody.registration_endpoint).toBeUndefined();

    // The endpoint itself still responds (panva returns 404) but our
    // rate-limit hook is not installed.
    const res = await fetch(`${s.baseUrl}/oidc/reg`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["http://127.0.0.1/callback"] }),
    });
    expect([400, 404]).toContain(res.status);
  });
});

describe("interaction routes", () => {
  let s: Setup;
  afterEach(async () => {
    if (s) await s.close();
  });

  it("returns 404 for an unknown interaction uid", async () => {
    s = await setup();
    const res = await fetch(`${s.baseUrl}/oidc/interaction/nope-does-not-exist`);
    expect(res.status).toBe(404);
  });

  it("returns 404 on POST /login for an unknown uid", async () => {
    s = await setup();
    const res = await fetch(`${s.baseUrl}/oidc/interaction/nope/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ challengeId: "x", credential: {} }),
    });
    expect(res.status).toBe(404);
  });
});
