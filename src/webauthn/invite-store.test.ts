import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  _resetInviteStore,
  consumeInviteSlot,
  createInviteSlot,
  findInviteByToken,
  findInviteForAccount,
  markInviteRegistered,
} from "./invite-store.js";

const ACCT_A = "00000000-0000-0000-0000-00000000000a";
const ACCT_B = "00000000-0000-0000-0000-00000000000b";

describe("invite-store", () => {
  beforeEach(() => _resetInviteStore());
  afterEach(() => _resetInviteStore());

  it("create returns a slot with a unique 43-char base64url token and 5min default TTL", () => {
    const slot = createInviteSlot({ accountId: ACCT_A, label: "Phone" });
    expect(slot.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(slot.expiresAt - slot.createdAt).toBe(5 * 60 * 1000);
    expect(slot.accountId).toBe(ACCT_A);
    expect(slot.label).toBe("Phone");
  });

  it("findInviteForAccount returns the active slot, null when none", () => {
    expect(findInviteForAccount(ACCT_A)).toBeNull();
    const slot = createInviteSlot({ accountId: ACCT_A, label: "Phone" });
    expect(findInviteForAccount(ACCT_A)?.token).toBe(slot.token);
  });

  it("creating a second invite for the same account supersedes the first", () => {
    const a = createInviteSlot({ accountId: ACCT_A, label: "Phone" });
    const b = createInviteSlot({ accountId: ACCT_A, label: "Tablet" });
    expect(a.token).not.toBe(b.token);
    expect(findInviteForAccount(ACCT_A)?.token).toBe(b.token);
    // The old token is no longer recognised — superseding is real, not just
    // "newest wins on lookup-by-account". A leaked old link can't be redeemed.
    expect(findInviteByToken(a.token)).toBeNull();
    expect(findInviteByToken(b.token)?.accountId).toBe(ACCT_A);
  });

  it("slots are isolated per account", () => {
    createInviteSlot({ accountId: ACCT_A, label: "A" });
    const b = createInviteSlot({ accountId: ACCT_B, label: "B" });
    expect(findInviteForAccount(ACCT_A)?.label).toBe("A");
    expect(findInviteForAccount(ACCT_B)?.label).toBe("B");
    expect(findInviteByToken(b.token)?.accountId).toBe(ACCT_B);
  });

  it("expired slots are dropped on read", () => {
    const slot = createInviteSlot({ accountId: ACCT_A, label: "Phone", ttlMs: 1 });
    // Wait past the expiry — TTL is in ms so a microtask + small sleep is enough.
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(findInviteForAccount(ACCT_A)).toBeNull();
        expect(findInviteByToken(slot.token)).toBeNull();
        resolve();
      }, 5);
    });
  });

  it("consumeInviteSlot removes the slot and returns it once", () => {
    const slot = createInviteSlot({ accountId: ACCT_A, label: "Phone" });
    const consumed = consumeInviteSlot(ACCT_A);
    expect(consumed?.token).toBe(slot.token);
    expect(consumeInviteSlot(ACCT_A)).toBeNull();
    expect(findInviteForAccount(ACCT_A)).toBeNull();
  });

  it("markInviteRegistered attaches a credentialId without consuming the slot", () => {
    const slot = createInviteSlot({ accountId: ACCT_A, label: "Phone" });
    expect(slot.credentialId).toBeNull();
    expect(markInviteRegistered(ACCT_A, "cred-123")).toBe(true);
    const after = findInviteForAccount(ACCT_A);
    expect(after?.credentialId).toBe("cred-123");
    // The same token still resolves — used by the rename PATCH that follows.
    expect(findInviteByToken(slot.token)?.credentialId).toBe("cred-123");
  });

  it("markInviteRegistered returns false when the slot is gone", () => {
    expect(markInviteRegistered(ACCT_A, "cred-123")).toBe(false);
  });
});
