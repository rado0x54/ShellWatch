import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDatabase, type DatabaseConnection } from "../connection.js";
import { runMigrations } from "../migrate.js";
import { accounts } from "../schema.js";
import { DrizzlePushSubscriptionRepository } from "./push-subscription-repo.js";

describe("DrizzlePushSubscriptionRepository.upsert ownership", () => {
  let conn: DatabaseConnection;
  let repo: DrizzlePushSubscriptionRepository;
  const ACCT_A = "00000000-0000-0000-0000-00000000000a";
  const ACCT_B = "00000000-0000-0000-0000-00000000000b";
  const ENDPOINT = "https://fcm.googleapis.com/fcm/send/abc";

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
    repo = new DrizzlePushSubscriptionRepository(conn.db);
  });

  afterEach(() => conn.close());

  it("first subscribe inserts a row", () => {
    const row = repo.upsert({ accountId: ACCT_A, endpoint: ENDPOINT, p256dh: "p1", auth: "a1" });
    expect(row).not.toBeNull();
    expect(row!.accountId).toBe(ACCT_A);
    expect(row!.p256dh).toBe("p1");
  });

  it("re-subscribe by same account rotates keys but keeps id and ownership", () => {
    const first = repo.upsert({
      accountId: ACCT_A,
      endpoint: ENDPOINT,
      p256dh: "p1",
      auth: "a1",
    })!;
    const second = repo.upsert({
      accountId: ACCT_A,
      endpoint: ENDPOINT,
      p256dh: "p2",
      auth: "a2",
    });
    expect(second).not.toBeNull();
    expect(second!.id).toBe(first.id);
    expect(second!.accountId).toBe(ACCT_A);
    expect(second!.p256dh).toBe("p2");
    expect(second!.auth).toBe("a2");
  });

  it("rejects subscribe when endpoint already belongs to another account", () => {
    repo.upsert({ accountId: ACCT_A, endpoint: ENDPOINT, p256dh: "p1", auth: "a1" });
    const hijack = repo.upsert({
      accountId: ACCT_B,
      endpoint: ENDPOINT,
      p256dh: "px",
      auth: "ax",
    });
    expect(hijack).toBeNull();

    // Confirm A's row is intact — accountId did not flip and keys were not overwritten.
    const stillA = repo.findByAccountId(ACCT_A);
    expect(stillA).toHaveLength(1);
    expect(stillA[0].p256dh).toBe("p1");
    expect(repo.findByAccountId(ACCT_B)).toHaveLength(0);
  });
});
