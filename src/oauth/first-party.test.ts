import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import Database from "better-sqlite3";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import type Provider from "oidc-provider";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultOAuthConfig } from "./config.js";
import { createFirstPartyTokenMinter, FIRST_PARTY_GRANT_TYPE } from "./first-party.js";
import { createOAuthProvider } from "./provider.js";
import { createSigningKeyService } from "./signing-keys.js";

type AnyDb = BetterSQLite3Database<Record<string, never>>;

interface Setup {
  provider: Provider;
  close: () => void;
}

async function setupProvider(): Promise<Setup> {
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
    db: db as never,
    config: { ...defaultOAuthConfig, enabled: true },
    signingKeyService,
  });

  return { provider, close: () => sqlite.close() };
}

describe("createFirstPartyTokenMinter", () => {
  let setup: Setup;

  beforeEach(async () => {
    setup = await setupProvider();
  });

  afterEach(() => {
    setup.close();
  });

  it("mints an access + refresh token pair bound to the given account", async () => {
    const minter = createFirstPartyTokenMinter(setup.provider, {
      accessTokenSeconds: 3600,
    });

    const tokens = await minter.mint({
      accountId: "acct_test_1",
      audience: "http://localhost/",
      scopes: ["mcp", "agent"],
    });

    expect(tokens.accessToken).toBeTruthy();
    expect(tokens.refreshToken).toBeTruthy();
    expect(tokens.accessToken).not.toBe(tokens.refreshToken);
    expect(tokens.accessTokenExpiresAt.getTime()).toBeGreaterThan(Date.now());
    expect(tokens.refreshTokenExpiresAt.getTime()).toBeGreaterThan(
      tokens.accessTokenExpiresAt.getTime(),
    );
  });

  it("produces an access token that `provider.AccessToken.find` can recover", async () => {
    const minter = createFirstPartyTokenMinter(setup.provider, {
      accessTokenSeconds: 3600,
    });

    const { accessToken } = await minter.mint({
      accountId: "acct_find_test",
      audience: "http://localhost/",
      scopes: ["mcp"],
    });

    const record = await setup.provider.AccessToken.find(accessToken);
    expect(record).toBeDefined();
    expect(record?.accountId).toBe("acct_find_test");
    expect(record?.aud).toBe("http://localhost/");
    expect(record?.scope).toContain("mcp");
    expect(record?.gty).toBe(FIRST_PARTY_GRANT_TYPE);
    expect(record?.clientId).toBe("ui-app");
  });

  it("pins the access token format to opaque (not JWT)", async () => {
    const minter = createFirstPartyTokenMinter(setup.provider, {
      accessTokenSeconds: 3600,
    });

    const { accessToken } = await minter.mint({
      accountId: "acct_fmt",
      audience: "http://localhost/",
      scopes: ["mcp"],
    });

    // Opaque tokens are a single short-ish base64url string. A JWT would
    // be three segments separated by dots.
    expect(accessToken.includes(".")).toBe(false);
  });

  it("binds both tokens to the same grant so a single revocation kills both", async () => {
    const minter = createFirstPartyTokenMinter(setup.provider, {
      accessTokenSeconds: 3600,
    });

    const { accessToken, refreshToken } = await minter.mint({
      accountId: "acct_revoke",
      audience: "http://localhost/",
      scopes: ["mcp"],
    });

    const accessRecord = await setup.provider.AccessToken.find(accessToken);
    const refreshRecord = await setup.provider.RefreshToken.find(refreshToken);
    expect(accessRecord?.grantId).toBeTruthy();
    expect(refreshRecord?.grantId).toBe(accessRecord?.grantId);
  });

  it("rejects empty accountId", async () => {
    const minter = createFirstPartyTokenMinter(setup.provider, {
      accessTokenSeconds: 3600,
    });
    await expect(
      minter.mint({ accountId: "", audience: "http://localhost/", scopes: ["mcp"] }),
    ).rejects.toThrow(/accountId is required/);
  });

  it("rejects empty audience", async () => {
    const minter = createFirstPartyTokenMinter(setup.provider, {
      accessTokenSeconds: 3600,
    });
    await expect(
      minter.mint({ accountId: "acct_1", audience: "", scopes: ["mcp"] }),
    ).rejects.toThrow(/audience is required/);
  });

  it("rejects empty scope list", async () => {
    const minter = createFirstPartyTokenMinter(setup.provider, {
      accessTokenSeconds: 3600,
    });
    await expect(
      minter.mint({
        accountId: "acct_1",
        audience: "http://localhost/",
        scopes: [],
      }),
    ).rejects.toThrow(/at least one scope/);
  });

  it("returned expiry times exactly match what panva persisted", async () => {
    // Asymmetry between the returned `expiresAt` and the server-side
    // token lifetime is what turns a silent refresh loop into a bug:
    // cookies drop early → user re-auths mid-session, or cookies
    // outlive tokens → silent 401 spam. Pin both via round-trip
    // through `provider.*.find` and compare.
    const minter = createFirstPartyTokenMinter(setup.provider, {
      accessTokenSeconds: 3600,
    });

    const tokens = await minter.mint({
      accountId: "acct_expiry",
      audience: "http://localhost/",
      scopes: ["mcp"],
    });

    const accessRecord = await setup.provider.AccessToken.find(tokens.accessToken);
    const refreshRecord = await setup.provider.RefreshToken.find(tokens.refreshToken);
    expect(accessRecord?.exp).toBe(Math.floor(tokens.accessTokenExpiresAt.getTime() / 1000));
    expect(refreshRecord?.exp).toBe(Math.floor(tokens.refreshTokenExpiresAt.getTime() / 1000));
  });
});
