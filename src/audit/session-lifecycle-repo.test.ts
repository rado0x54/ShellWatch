// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDatabase, type DatabaseConnection } from "../db/connection.js";
import { runMigrations } from "../db/migrate.js";
import { accounts, endpoints } from "../db/schema.js";
import { DrizzleSessionLifecycleRepository } from "./session-lifecycle-repo.js";

describe("DrizzleSessionLifecycleRepository", () => {
  let conn: DatabaseConnection;
  let repo: DrizzleSessionLifecycleRepository;
  const ACCT_A = "00000000-0000-0000-0000-00000000000a";
  const ACCT_B = "00000000-0000-0000-0000-00000000000b";
  const ENDPOINT_A1 = "00000000-0000-0000-0000-0000000000a1";
  const ENDPOINT_A2 = "00000000-0000-0000-0000-0000000000a2";
  const ENDPOINT_B1 = "00000000-0000-0000-0000-0000000000b1";

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
    conn.db
      .insert(endpoints)
      .values([
        {
          id: ENDPOINT_A1,
          accountId: ACCT_A,
          label: "A1",
          host: "h",
          port: 22,
          username: "u",
          createdAt: now,
          updatedAt: now,
        },
        {
          id: ENDPOINT_A2,
          accountId: ACCT_A,
          label: "A2",
          host: "h",
          port: 22,
          username: "u",
          createdAt: now,
          updatedAt: now,
        },
        {
          id: ENDPOINT_B1,
          accountId: ACCT_B,
          label: "B1",
          host: "h",
          port: 22,
          username: "u",
          createdAt: now,
          updatedAt: now,
        },
      ])
      .run();
    repo = new DrizzleSessionLifecycleRepository(conn.db);
  });

  afterEach(() => conn.close());

  function seed(opts: {
    sessionId: string;
    accountId: string;
    endpointId: string;
    createdAt: string;
  }) {
    repo.insertOpen({
      sessionId: opts.sessionId,
      accountId: opts.accountId,
      endpointId: opts.endpointId,
      source: "ui",
      status: "open",
      createdAt: opts.createdAt,
    });
  }

  describe("list ordering and cursor", () => {
    it("returns rows newest-first and pages deterministically across boundaries", () => {
      // Seed 5 rows for ACCT_A across two timestamps to exercise the secondary
      // session_id sort. Two share createdAt to force the keyset tie-break.
      seed({
        sessionId: "s1",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-01T00:00:00Z",
      });
      seed({
        sessionId: "s2",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-02T00:00:00Z",
      });
      seed({
        sessionId: "s3",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-03T00:00:00Z",
      });
      seed({
        sessionId: "s4",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-03T00:00:00Z",
      });
      seed({
        sessionId: "s5",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-04T00:00:00Z",
      });

      const page1 = repo.list(ACCT_A, {}, { limit: 2 });
      expect(page1.rows.map((r) => r.sessionId)).toEqual(["s5", "s4"]);
      expect(page1.nextCursor).not.toBeNull();

      const page2 = repo.list(ACCT_A, {}, { cursor: page1.nextCursor!, limit: 2 });
      // s4 and s3 share createdAt; s4 sorts first (string DESC). s3 follows.
      // Then s2.
      expect(page2.rows.map((r) => r.sessionId)).toEqual(["s3", "s2"]);
      expect(page2.nextCursor).not.toBeNull();

      const page3 = repo.list(ACCT_A, {}, { cursor: page2.nextCursor!, limit: 2 });
      expect(page3.rows.map((r) => r.sessionId)).toEqual(["s1"]);
      expect(page3.nextCursor).toBeNull();
    });

    it("malformed cursor degrades to first page", () => {
      seed({
        sessionId: "s1",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-01T00:00:00Z",
      });
      const page = repo.list(ACCT_A, {}, { cursor: "not-base64-anything" });
      expect(page.rows.map((r) => r.sessionId)).toEqual(["s1"]);
    });
  });

  describe("account scoping", () => {
    it("never returns rows owned by a different account", () => {
      seed({
        sessionId: "a1",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-01T00:00:00Z",
      });
      seed({
        sessionId: "b1",
        accountId: ACCT_B,
        endpointId: ENDPOINT_B1,
        createdAt: "2026-01-02T00:00:00Z",
      });

      const aPage = repo.list(ACCT_A, {}, {});
      expect(aPage.rows.map((r) => r.sessionId)).toEqual(["a1"]);

      const bPage = repo.list(ACCT_B, {}, {});
      expect(bPage.rows.map((r) => r.sessionId)).toEqual(["b1"]);
    });
  });

  describe("endpointId filter", () => {
    it("narrows to the requested endpoint within the account", () => {
      seed({
        sessionId: "x",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-01T00:00:00Z",
      });
      seed({
        sessionId: "y",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A2,
        createdAt: "2026-01-02T00:00:00Z",
      });

      const page = repo.list(ACCT_A, { endpointId: ENDPOINT_A1 }, {});
      expect(page.rows.map((r) => r.sessionId)).toEqual(["x"]);
    });
  });

  describe("from/to filter", () => {
    beforeEach(() => {
      seed({
        sessionId: "early",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-01T00:00:00Z",
      });
      seed({
        sessionId: "mid",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-15T12:00:00Z",
      });
      seed({
        sessionId: "late",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-02-01T00:00:00Z",
      });
    });

    it("from is inclusive lower bound", () => {
      const page = repo.list(ACCT_A, { from: "2026-01-15T00:00:00Z" }, {});
      expect(page.rows.map((r) => r.sessionId)).toEqual(["late", "mid"]);
    });

    it("to is inclusive upper bound", () => {
      const page = repo.list(ACCT_A, { to: "2026-01-15T23:59:59.999Z" }, {});
      expect(page.rows.map((r) => r.sessionId)).toEqual(["mid", "early"]);
    });

    it("from + to brackets the window", () => {
      const page = repo.list(
        ACCT_A,
        { from: "2026-01-10T00:00:00Z", to: "2026-01-20T00:00:00Z" },
        {},
      );
      expect(page.rows.map((r) => r.sessionId)).toEqual(["mid"]);
    });

    it("composes with endpointId filter", () => {
      seed({
        sessionId: "other-ep",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A2,
        createdAt: "2026-01-15T12:00:00Z",
      });
      const page = repo.list(
        ACCT_A,
        {
          endpointId: ENDPOINT_A1,
          from: "2026-01-10T00:00:00Z",
          to: "2026-01-20T00:00:00Z",
        },
        {},
      );
      expect(page.rows.map((r) => r.sessionId)).toEqual(["mid"]);
    });
  });

  describe("recordClose idempotency", () => {
    it("only the first close call wins; later calls do not overwrite timing", () => {
      seed({
        sessionId: "s",
        accountId: ACCT_A,
        endpointId: ENDPOINT_A1,
        createdAt: "2026-01-01T00:00:00Z",
      });

      repo.recordClose({
        sessionId: "s",
        status: "error",
        closedAt: "2026-01-01T00:05:00Z",
        durationMs: 5 * 60 * 1000,
        closeReason: "transport-error",
      });

      // Simulate the shutdown clobber path: error -> closed.
      repo.recordClose({
        sessionId: "s",
        status: "closed",
        closedAt: "2026-01-01T08:00:00Z",
        durationMs: 8 * 60 * 60 * 1000,
        closeReason: "shutdown",
      });

      const [row] = repo.list(ACCT_A, {}, {}).rows;
      expect(row?.status).toBe("error");
      expect(row?.closedAt).toBe("2026-01-01T00:05:00Z");
      expect(row?.durationMs).toBe(5 * 60 * 1000);
      expect(row?.closeReason).toBe("transport-error");
    });
  });
});
