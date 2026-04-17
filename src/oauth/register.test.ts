import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import Database from "better-sqlite3";
import Fastify, { type FastifyInstance } from "fastify";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import type Provider from "oidc-provider";
import { afterEach, describe, expect, it } from "vitest";
import type { Config } from "../config/index.js";
import { StubAccountRepository } from "../db/index.js";
import { defaultOAuthConfig } from "./config.js";
import { FIRST_PARTY_CLIENT_ID } from "./provider.js";
import { registerOAuth } from "./register.js";

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

type AnyDb = BetterSQLite3Database<Record<string, never>>;

interface Setup {
  app: FastifyInstance;
  db: AnyDb;
  baseUrl: string;
  provider: Provider;
  close: () => Promise<void>;
}

/**
 * Listens on an ephemeral port and constructs the OAuth provider with an
 * issuer matching that port, so every request the tests fire is consistent
 * with what panva expects (issuer-URL routing is strict).
 *
 * `app.inject()` doesn't work here because panva/Koa writes to a real
 * `ServerResponse` stream and light-my-request's mock doesn't drive the
 * necessary events. A real HTTP listener is the minimum fidelity needed.
 */
async function setupOAuthApp(overrides: Partial<typeof defaultOAuthConfig> = {}): Promise<Setup> {
  const sqlite = new Database(":memory:");
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  const db = drizzle(sqlite, { schema: {} });
  migrate(db, { migrationsFolder: resolve(import.meta.dirname, "../../drizzle") });

  // Pre-bind a port by creating a throwaway listener, grabbing the port, and
  // closing it before Fastify starts. Fastify's listen({ port: 0 }) would
  // give us a port too, but we need the port known BEFORE we call
  // registerOAuth (so the issuer URL embeds it).
  const { createServer } = await import("node:net");
  const probe = createServer();
  await new Promise<void>((resolve_) => probe.listen(0, "127.0.0.1", resolve_));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve_) => probe.close(() => resolve_()));

  const baseUrl = `http://127.0.0.1:${port}`;

  const app = Fastify({ logger: false });

  const result = await registerOAuth({
    app,
    db: db as never,
    config: { ...defaultOAuthConfig, ...overrides },
    baseUrl,
    sessionSecret: randomBytes(32).toString("hex"),
    accountRepo: new StubAccountRepository(),
    security: testSecurity,
  });
  if (!result) throw new Error("registerOAuth unexpectedly returned null");

  await app.listen({ port, host: "127.0.0.1" });

  return {
    app,
    db,
    baseUrl,
    provider: result.provider,
    close: async () => {
      await app.close();
      sqlite.close();
    },
  };
}

describe("registerOAuth", () => {
  let setup: Setup;

  afterEach(async () => {
    if (setup) await setup.close();
  });

  // The previous "mounts nothing when disabled" test is obsolete: the
  // `oauth.enabled` config knob has been removed. Callers that want
  // OAuth absent simply don't call `registerOAuth` — there is no
  // partial-OAuth shape in the schema to assert against.

  it("serves RFC 8414 authorization server metadata at the issuer path", async () => {
    setup = await setupOAuthApp();
    const res = await fetch(`${setup.baseUrl}/oidc/.well-known/openid-configuration`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;

    expect(body.issuer).toBe(`${setup.baseUrl}/oidc`);
    expect(body.authorization_endpoint).toBe(`${setup.baseUrl}/oidc/auth`);
    expect(body.token_endpoint).toBe(`${setup.baseUrl}/oidc/token`);
    expect(body.jwks_uri).toBe(`${setup.baseUrl}/oidc/jwks`);
    expect(body.registration_endpoint).toBe(`${setup.baseUrl}/oidc/reg`);
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
    expect(body.grant_types_supported).toContain("authorization_code");
    expect(body.response_types_supported).toContain("code");
    expect(body.revocation_endpoint).toBe(`${setup.baseUrl}/oidc/token/revocation`);
  });

  it("registers the static first-party client", async () => {
    setup = await setupOAuthApp();
    const client = await setup.provider.Client.find(FIRST_PARTY_CLIENT_ID);
    expect(client).toBeDefined();
    expect(client?.clientId).toBe(FIRST_PARTY_CLIENT_ID);
    expect(client?.tokenEndpointAuthMethod).toBe("none");
  });

  it("advertises the configured scopes", async () => {
    setup = await setupOAuthApp({ scopes: ["mcp", "agent", "custom"] });
    const res = await fetch(`${setup.baseUrl}/oidc/.well-known/openid-configuration`);
    const body = (await res.json()) as Record<string, unknown>;
    const scopes = body.scopes_supported as string[];
    expect(scopes).toEqual(expect.arrayContaining(["mcp", "agent", "custom"]));
  });

  it("omits registration_endpoint when DCR is disabled", async () => {
    setup = await setupOAuthApp({ dynamicClientRegistration: "disabled" });
    const res = await fetch(`${setup.baseUrl}/oidc/.well-known/openid-configuration`);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.registration_endpoint).toBeUndefined();
  });

  it("serves JWKS with a non-empty key set", async () => {
    setup = await setupOAuthApp();
    const res = await fetch(`${setup.baseUrl}/oidc/jwks`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keys: Array<Record<string, unknown>> };
    expect(body.keys.length).toBeGreaterThan(0);
    expect(body.keys[0]!.kty).toBe("OKP");
    expect(body.keys[0]!.crv).toBe("Ed25519");
    expect(body.keys[0]!.alg).toBe("EdDSA");
    expect(body.keys[0]!.d).toBeUndefined(); // public JWKS — no private component
  });

  it("does not intercept non-/oidc requests", async () => {
    const sqlite = new Database(":memory:");
    sqlite.pragma("journal_mode = WAL");
    const db = drizzle(sqlite, { schema: {} });
    migrate(db, { migrationsFolder: resolve(import.meta.dirname, "../../drizzle") });

    const app = Fastify({ logger: false });
    app.get("/unrelated", async () => ({ status: "not-oauth" }));

    await registerOAuth({
      app,
      db: db as never,
      config: { ...defaultOAuthConfig },
      baseUrl: "http://localhost",
      sessionSecret: randomBytes(32).toString("hex"),
      accountRepo: new StubAccountRepository(),
      security: testSecurity,
    });

    const address = await app.listen({ port: 0, host: "127.0.0.1" });
    const res = await fetch(`${address}/unrelated`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "not-oauth" });

    await app.close();
    sqlite.close();
  });
});
