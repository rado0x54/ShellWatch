import { resolve } from "node:path";
import Database from "better-sqlite3";
import { eq } from "drizzle-orm";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import type { AdapterPayload } from "oidc-provider";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DrizzleOidcAdapter, createDrizzleAdapterFactory } from "./drizzle-adapter.js";
import { oauthAccessTokens, oauthAuthorizationCodes, oauthSessions } from "./schema.js";

type AnyDb = BetterSQLite3Database<Record<string, never>>;

/**
 * Spin up an in-memory SQLite with all migrations applied. Each test gets a
 * fresh DB so tests don't leak into each other.
 */
function setupDb(): { db: AnyDb; close: () => void } {
  const sqlite = new Database(":memory:");
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  const db = drizzle(sqlite, { schema: {} });
  migrate(db, { migrationsFolder: resolve(import.meta.dirname, "../../../drizzle") });
  return {
    db,
    close: () => sqlite.close(),
  };
}

describe("DrizzleOidcAdapter", () => {
  let setup: ReturnType<typeof setupDb>;

  beforeEach(() => {
    setup = setupDb();
  });

  afterEach(() => {
    setup.close();
  });

  describe("upsert / find", () => {
    it("stores and retrieves a payload verbatim", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAccessTokens);
      const payload: AdapterPayload = {
        jti: "abc123",
        iat: 1700000000,
        exp: 1700003600,
        accountId: "acct_1",
        scope: "mcp",
      };
      await adapter.upsert("abc123", payload, 3600);
      expect(await adapter.find("abc123")).toEqual(payload);
    });

    it("returns undefined for missing ids", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAccessTokens);
      expect(await adapter.find("does-not-exist")).toBeUndefined();
    });

    it("overwrites on re-upsert", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAccessTokens);
      await adapter.upsert("id1", { scope: "mcp" } as AdapterPayload, 60);
      await adapter.upsert("id1", { scope: "agent" } as AdapterPayload, 60);
      const found = await adapter.find("id1");
      expect(found).toEqual({ scope: "agent" });
    });

    it("preserves created_at across re-upsert (audit / TTL-from-creation invariant)", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAccessTokens);
      await adapter.upsert("id1", { scope: "mcp" } as AdapterPayload, 60);

      const [firstRow] = await setup.db
        .select()
        .from(oauthAccessTokens)
        .where(eq(oauthAccessTokens.id, "id1"));
      const firstCreatedAt = firstRow!.createdAt;

      // Wait a tick so a naive "set createdAt = now()" bug would visibly
      // produce a later ISO string.
      await new Promise((r) => setTimeout(r, 20));

      await adapter.upsert("id1", { scope: "agent" } as AdapterPayload, 60);

      const [secondRow] = await setup.db
        .select()
        .from(oauthAccessTokens)
        .where(eq(oauthAccessTokens.id, "id1"));
      expect(secondRow!.createdAt).toBe(firstCreatedAt);
      expect(secondRow!.payload).toEqual({ scope: "agent" });
    });

    it("returns payload even after expires_at has passed (panva inspects exp itself)", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAccessTokens);
      await adapter.upsert("expired-id", { jti: "expired" } as AdapterPayload, -1);
      // We do not filter by expires_at at the SQL layer — panva's application
      // layer rejects stale records via payload.exp. Our find returns the row.
      expect(await adapter.find("expired-id")).toEqual({ jti: "expired" });
    });
  });

  describe("findByUserCode", () => {
    it("indexes userCode for device-flow lookups", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAccessTokens);
      await adapter.upsert("dev-1", { userCode: "WXYZ-1234" } as unknown as AdapterPayload, 60);
      const found = await adapter.findByUserCode("WXYZ-1234");
      expect(found).toEqual({ userCode: "WXYZ-1234" });
    });

    it("returns undefined when userCode absent", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAccessTokens);
      expect(await adapter.findByUserCode("nope")).toBeUndefined();
    });
  });

  describe("findByUid", () => {
    it("indexes uid for session lookups", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthSessions);
      await adapter.upsert("sess-1", { uid: "uid-abc" } as unknown as AdapterPayload, 60);
      const found = await adapter.findByUid("uid-abc");
      expect(found).toEqual({ uid: "uid-abc" });
    });
  });

  describe("consume", () => {
    it("stamps payload.consumed and is idempotent", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAuthorizationCodes);
      await adapter.upsert("code-1", { jti: "code-1" } as AdapterPayload, 60);

      await adapter.consume("code-1");
      const after = (await adapter.find("code-1")) as AdapterPayload & { consumed?: number };
      expect(typeof after?.consumed).toBe("number");
      expect(after?.consumed).toBeGreaterThan(0);

      const firstStamp = after?.consumed;
      await adapter.consume("code-1");
      const afterSecond = (await adapter.find("code-1")) as AdapterPayload & { consumed?: number };
      expect(afterSecond?.consumed).toBeGreaterThanOrEqual(firstStamp!);
    });

    it("is a no-op for missing ids", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAuthorizationCodes);
      await expect(adapter.consume("nope")).resolves.toBeUndefined();
    });
  });

  describe("destroy", () => {
    it("removes the row", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAccessTokens);
      await adapter.upsert("id1", {} as AdapterPayload, 60);
      await adapter.destroy("id1");
      expect(await adapter.find("id1")).toBeUndefined();
    });
  });

  describe("revokeByGrantId", () => {
    it("removes all rows in this model with the matching grant_id", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAccessTokens);
      await adapter.upsert("a", { grantId: "grant-1" } as unknown as AdapterPayload, 60);
      await adapter.upsert("b", { grantId: "grant-1" } as unknown as AdapterPayload, 60);
      await adapter.upsert("c", { grantId: "grant-2" } as unknown as AdapterPayload, 60);

      await adapter.revokeByGrantId("grant-1");

      expect(await adapter.find("a")).toBeUndefined();
      expect(await adapter.find("b")).toBeUndefined();
      expect(await adapter.find("c")).toEqual({ grantId: "grant-2" });
    });

    it("does nothing for an unknown grant", async () => {
      const adapter = new DrizzleOidcAdapter(setup.db as never, oauthAccessTokens);
      await adapter.upsert("x", { grantId: "grant-1" } as unknown as AdapterPayload, 60);
      await adapter.revokeByGrantId("nope");
      expect(await adapter.find("x")).toEqual({ grantId: "grant-1" });
    });
  });
});

describe("createDrizzleAdapterFactory", () => {
  let setup: ReturnType<typeof setupDb>;

  beforeEach(() => {
    setup = setupDb();
  });

  afterEach(() => {
    setup.close();
  });

  it("returns a working adapter for a known model", async () => {
    const factory = createDrizzleAdapterFactory(setup.db as never);
    const adapter = factory("AccessToken");
    await adapter.upsert("x", { jti: "x" } as AdapterPayload, 60);
    expect(await adapter.find("x")).toEqual({ jti: "x" });
  });

  it("throws for unknown models", () => {
    const factory = createDrizzleAdapterFactory(setup.db as never);
    expect(() => factory("NotAModel")).toThrow(/unknown panva model/);
  });

  it("supports all 14 panva models", () => {
    const factory = createDrizzleAdapterFactory(setup.db as never);
    const allModels = [
      "Session",
      "AccessToken",
      "AuthorizationCode",
      "RefreshToken",
      "DeviceCode",
      "ClientCredentials",
      "Client",
      "InitialAccessToken",
      "RegistrationAccessToken",
      "Interaction",
      "ReplayDetection",
      "PushedAuthorizationRequest",
      "BackchannelAuthenticationRequest",
      "Grant",
    ];
    for (const m of allModels) {
      expect(() => factory(m)).not.toThrow();
    }
  });
});
