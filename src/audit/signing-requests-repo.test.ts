import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDatabase, type DatabaseConnection } from "../db/connection.js";
import { runMigrations } from "../db/migrate.js";
import { accounts } from "../db/schema.js";
import {
  DrizzleSigningRequestsRepository,
  type SigningRequestInsert,
} from "./signing-requests-repo.js";

describe("DrizzleSigningRequestsRepository", () => {
  let conn: DatabaseConnection;
  let repo: DrizzleSigningRequestsRepository;
  const ACCT_A = "00000000-0000-0000-0000-00000000000a";
  const ACCT_B = "00000000-0000-0000-0000-00000000000b";

  beforeEach(() => {
    conn = createDatabase(":memory:");
    runMigrations(conn.db);
    const now = new Date().toISOString();
    conn.db
      .insert(accounts)
      .values([
        { id: ACCT_A, name: "A", createdAt: now, updatedAt: now },
        { id: ACCT_B, name: "B", createdAt: now, updatedAt: now },
      ])
      .run();
    repo = new DrizzleSigningRequestsRepository(conn.db);
  });

  afterEach(() => conn.close());

  function seed(opts: Partial<SigningRequestInsert> & { id: string; createdAt: string }) {
    repo.insertCreated({
      accountId: ACCT_A,
      type: "webauthn-sign",
      source: "endpoint-auth",
      ...opts,
    });
  }

  describe("list ordering and cursor", () => {
    it("returns rows newest-first and pages deterministically across timestamp ties", () => {
      seed({ id: "r1", createdAt: "2026-01-01T00:00:00Z" });
      seed({ id: "r2", createdAt: "2026-01-02T00:00:00Z" });
      seed({ id: "r3", createdAt: "2026-01-03T00:00:00Z" });
      seed({ id: "r4", createdAt: "2026-01-03T00:00:00Z" });
      seed({ id: "r5", createdAt: "2026-01-04T00:00:00Z" });

      const p1 = repo.list(ACCT_A, {}, { limit: 2 });
      expect(p1.rows.map((r) => r.id)).toEqual(["r5", "r4"]);
      expect(p1.nextCursor).not.toBeNull();

      const p2 = repo.list(ACCT_A, {}, { cursor: p1.nextCursor!, limit: 2 });
      expect(p2.rows.map((r) => r.id)).toEqual(["r3", "r2"]);

      const p3 = repo.list(ACCT_A, {}, { cursor: p2.nextCursor!, limit: 2 });
      expect(p3.rows.map((r) => r.id)).toEqual(["r1"]);
      expect(p3.nextCursor).toBeNull();
    });

    it("malformed cursor degrades to first page", () => {
      seed({ id: "r1", createdAt: "2026-01-01T00:00:00Z" });
      const page = repo.list(ACCT_A, {}, { cursor: "not-base64-anything" });
      expect(page.rows.map((r) => r.id)).toEqual(["r1"]);
    });
  });

  describe("account scoping", () => {
    it("never returns rows owned by a different account", () => {
      seed({ id: "a1", createdAt: "2026-01-01T00:00:00Z" });
      seed({ id: "b1", accountId: ACCT_B, createdAt: "2026-01-02T00:00:00Z" });

      expect(repo.list(ACCT_A, {}, {}).rows.map((r) => r.id)).toEqual(["a1"]);
      expect(repo.list(ACCT_B, {}, {}).rows.map((r) => r.id)).toEqual(["b1"]);
    });

    it("getById refuses cross-account reads", () => {
      seed({ id: "a1", createdAt: "2026-01-01T00:00:00Z" });
      expect(repo.getById(ACCT_B, "a1")).toBeNull();
      expect(repo.getById(ACCT_A, "a1")?.id).toBe("a1");
    });
  });

  describe("filters", () => {
    beforeEach(() => {
      seed({
        id: "wa-proxy",
        type: "webauthn-sign",
        source: "agent-proxy",
        credentialId: "cred-1",
        createdAt: "2026-01-01T00:00:00Z",
      });
      seed({
        id: "ka-fwd",
        type: "key-approve",
        source: "agent-forwarding",
        sessionId: "sess_a",
        createdAt: "2026-01-02T00:00:00Z",
      });
      seed({
        id: "wa-auth",
        type: "webauthn-sign",
        source: "endpoint-auth",
        credentialId: "cred-2",
        createdAt: "2026-01-03T00:00:00Z",
      });
    });

    it("source filter narrows to one source", () => {
      const page = repo.list(ACCT_A, { source: "agent-proxy" }, {});
      expect(page.rows.map((r) => r.id)).toEqual(["wa-proxy"]);
    });

    it("from/to bracket time window", () => {
      const page = repo.list(
        ACCT_A,
        { from: "2026-01-02T00:00:00Z", to: "2026-01-02T23:59:59Z" },
        {},
      );
      expect(page.rows.map((r) => r.id)).toEqual(["ka-fwd"]);
    });
  });

  describe("recordResolution", () => {
    it("sets outcome, resolved_at, latency_ms, cancel_reason", () => {
      seed({ id: "r", createdAt: "2026-01-01T00:00:00Z" });
      repo.recordResolution({
        id: "r",
        outcome: "approved",
        resolvedAt: "2026-01-01T00:00:00.250Z",
        latencyMs: 250,
      });
      const [row] = repo.list(ACCT_A, {}, {}).rows;
      expect(row?.outcome).toBe("approved");
      expect(row?.latencyMs).toBe(250);
      expect(row?.cancelReason).toBeNull();
    });

    it("first resolution wins; later calls do not overwrite", () => {
      seed({ id: "r", createdAt: "2026-01-01T00:00:00Z" });
      repo.recordResolution({
        id: "r",
        outcome: "denied",
        resolvedAt: "2026-01-01T00:00:00.500Z",
        latencyMs: 500,
      });
      // Late cancel arriving after the deny should not clobber the first write.
      repo.recordResolution({
        id: "r",
        outcome: "cancelled",
        resolvedAt: "2026-01-01T01:00:00Z",
        latencyMs: 3_600_000,
        cancelReason: "ssh-disconnect",
      });
      const [row] = repo.list(ACCT_A, {}, {}).rows;
      expect(row?.outcome).toBe("denied");
      expect(row?.latencyMs).toBe(500);
      expect(row?.cancelReason).toBeNull();
    });

    it("filterable by outcome after resolution", () => {
      seed({ id: "ok", createdAt: "2026-01-01T00:00:00Z" });
      seed({ id: "no", createdAt: "2026-01-01T00:00:01Z" });
      repo.recordResolution({
        id: "ok",
        outcome: "approved",
        resolvedAt: "2026-01-01T00:00:00.100Z",
        latencyMs: 100,
      });
      repo.recordResolution({
        id: "no",
        outcome: "denied",
        resolvedAt: "2026-01-01T00:00:01.200Z",
        latencyMs: 200,
      });
      expect(repo.list(ACCT_A, { outcome: "approved" }, {}).rows.map((r) => r.id)).toEqual(["ok"]);
      expect(repo.list(ACCT_A, { outcome: "denied" }, {}).rows.map((r) => r.id)).toEqual(["no"]);
    });
  });

  describe("account cascade", () => {
    it("rows are deleted when the parent account is removed", async () => {
      seed({ id: "r", createdAt: "2026-01-01T00:00:00Z" });
      // Manually delete the account — production cleanup goes through cleanup.ts
      // which deletes child tables in FK order; here we exercise the CASCADE on
      // audit_signing_requests directly.
      const { eq } = await import("drizzle-orm");
      conn.db.delete(accounts).where(eq(accounts.id, ACCT_A)).run();
      expect(repo.list(ACCT_A, {}, {}).rows).toEqual([]);
    });
  });
});
