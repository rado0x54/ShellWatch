import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDatabase, type DatabaseConnection } from "../connection.js";
import { runMigrations } from "../migrate.js";
import { accounts, webauthnCredentials } from "../schema.js";
import {
  DrizzlePasskeyInviteRepository,
  inviteStatus,
  PASSKEY_INVITE_TTL_MS,
} from "./passkey-invite-repo.js";

const ACCT = "00000000-0000-0000-0000-000000000001";
const OTHER_ACCT = "00000000-0000-0000-0000-000000000002";

describe("DrizzlePasskeyInviteRepository", () => {
  let conn: DatabaseConnection;
  let repo: DrizzlePasskeyInviteRepository;

  beforeEach(() => {
    conn = createDatabase(":memory:");
    runMigrations(conn.db);
    const now = new Date().toISOString();
    conn.db
      .insert(accounts)
      .values([
        { id: ACCT, name: "A", createdAt: now, updatedAt: now },
        { id: OTHER_ACCT, name: "B", createdAt: now, updatedAt: now },
      ])
      .run();
    repo = new DrizzlePasskeyInviteRepository(conn.db);
  });

  afterEach(() => conn.close());

  it("creates an invite with default 1h TTL and a unique 43-char base64url token", () => {
    const a = repo.create({ accountId: ACCT, label: "Phone" });
    const b = repo.create({ accountId: ACCT, label: "Tablet" });
    expect(a.token).not.toBe(b.token);
    expect(a.token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a.token.length).toBe(43);

    const ttl = Date.parse(a.expiresAt) - Date.parse(a.createdAt);
    expect(ttl).toBe(PASSKEY_INVITE_TTL_MS);
  });

  it("looks up by token and id+accountId, scoped per account", () => {
    const inv = repo.create({ accountId: ACCT, label: "Phone" });
    expect(repo.findByToken(inv.token)?.id).toBe(inv.id);
    expect(repo.findByIdForAccount(inv.id, ACCT)?.id).toBe(inv.id);
    // Cross-account lookup must miss.
    expect(repo.findByIdForAccount(inv.id, OTHER_ACCT)).toBeNull();
  });

  it("inviteStatus reflects pending / expired / revoked transitions", () => {
    const inv = repo.create({ accountId: ACCT, label: "Phone", ttlMs: 1000 });
    expect(inviteStatus(inv)).toBe("pending");

    // Manually expire by reading now > expiresAt.
    const future = new Date(Date.parse(inv.expiresAt) + 1);
    expect(inviteStatus(inv, future)).toBe("expired");

    repo.revoke(inv.id, ACCT);
    const revoked = repo.findById(inv.id)!;
    expect(inviteStatus(revoked)).toBe("revoked");
  });

  it("markConsumed sets consumedAt + credentialId; second call against the same id is a no-op", () => {
    const inv = repo.create({ accountId: ACCT, label: "Phone" });
    const credId1 = insertFakeCredential(conn);
    const credId2 = insertFakeCredential(conn);

    const ok1 = repo.markConsumed(inv.id, credId1);
    expect(ok1).toBe(true);
    const after1 = repo.findById(inv.id)!;
    expect(after1.consumedAt).not.toBeNull();
    expect(after1.credentialId).toBe(credId1);
    const consumedAt1 = after1.consumedAt;

    const ok2 = repo.markConsumed(inv.id, credId2);
    expect(ok2).toBe(false);
    const after2 = repo.findById(inv.id)!;
    expect(after2.consumedAt).toBe(consumedAt1);
    expect(after2.credentialId).toBe(credId1);
    expect(inviteStatus(after2)).toBe("registered");
  });

  it("revoke is scoped to account — wrong accountId is a no-op", () => {
    const inv = repo.create({ accountId: ACCT, label: "Phone" });
    expect(repo.revoke(inv.id, OTHER_ACCT)).toBe(false);
    const stillPending = repo.findById(inv.id)!;
    expect(stillPending.revokedAt).toBeNull();
    expect(repo.revoke(inv.id, ACCT)).toBe(true);
    expect(repo.findById(inv.id)!.revokedAt).not.toBeNull();
  });

  it("listForAccount returns only invites owned by the account", () => {
    repo.create({ accountId: ACCT, label: "A1" });
    repo.create({ accountId: ACCT, label: "A2" });
    repo.create({ accountId: OTHER_ACCT, label: "B1" });
    const list = repo.listForAccount(ACCT);
    expect(list).toHaveLength(2);
    expect(list.every((i) => i.accountId === ACCT)).toBe(true);
  });
});

// Inserts a real webauthn_credentials row so markConsumed's FK to credentialId
// is satisfied. Returns the row's primary key.
function insertFakeCredential(conn: DatabaseConnection): string {
  const id = `cred-${Math.random().toString(36).slice(2)}`;
  conn.db
    .insert(webauthnCredentials)
    .values({
      id,
      accountId: ACCT,
      credentialId: `webauthn-${id}`,
      publicKey: Buffer.alloc(0),
      label: `test-${id}`,
      createdAt: new Date().toISOString(),
      state: "pending_confirmation",
    })
    .run();
  return id;
}
