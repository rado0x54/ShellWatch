import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  _resetInviteStore,
  consumeInviteSlot,
  consumeInviteSlotIfTokenMatches,
  createInviteSlot,
  findInviteByToken,
  findInviteForAccount,
} from "./invite-store.js";

const ACCT_A = "00000000-0000-0000-0000-00000000000a";
const ACCT_B = "00000000-0000-0000-0000-00000000000b";

describe("invite-store", () => {
  beforeEach(() => _resetInviteStore());
  afterEach(() => _resetInviteStore());

  it("create returns a slot with a unique 43-char base64url token and 5min default TTL", () => {
    const slot = createInviteSlot({ accountId: ACCT_A });
    expect(slot.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(slot.expiresAt - slot.createdAt).toBe(5 * 60 * 1000);
    expect(slot.accountId).toBe(ACCT_A);
  });

  it("findInviteForAccount returns the active slot, null when none", () => {
    expect(findInviteForAccount(ACCT_A)).toBeNull();
    const slot = createInviteSlot({ accountId: ACCT_A });
    expect(findInviteForAccount(ACCT_A)?.token).toBe(slot.token);
  });

  it("creating a second invite for the same account supersedes the first", () => {
    const a = createInviteSlot({ accountId: ACCT_A });
    const b = createInviteSlot({ accountId: ACCT_A });
    expect(a.token).not.toBe(b.token);
    expect(findInviteForAccount(ACCT_A)?.token).toBe(b.token);
    // The old token is no longer recognised — superseding is real, not just
    // "newest wins on lookup-by-account". A leaked old link can't be redeemed.
    expect(findInviteByToken(a.token)).toBeNull();
    expect(findInviteByToken(b.token)?.accountId).toBe(ACCT_A);
  });

  it("slots are isolated per account", () => {
    const a = createInviteSlot({ accountId: ACCT_A });
    const b = createInviteSlot({ accountId: ACCT_B });
    expect(findInviteForAccount(ACCT_A)?.token).toBe(a.token);
    expect(findInviteForAccount(ACCT_B)?.token).toBe(b.token);
    expect(findInviteByToken(b.token)?.accountId).toBe(ACCT_B);
  });

  it("expired slots are dropped on read", () => {
    const slot = createInviteSlot({ accountId: ACCT_A, ttlMs: 1 });
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(findInviteForAccount(ACCT_A)).toBeNull();
        expect(findInviteByToken(slot.token)).toBeNull();
        resolve();
      }, 5);
    });
  });

  it("consumeInviteSlot removes the slot and returns it once", () => {
    const slot = createInviteSlot({ accountId: ACCT_A });
    const consumed = consumeInviteSlot(ACCT_A);
    expect(consumed?.token).toBe(slot.token);
    expect(consumeInviteSlot(ACCT_A)).toBeNull();
    expect(findInviteForAccount(ACCT_A)).toBeNull();
  });

  it("consumeInviteSlotIfTokenMatches refuses to delete a superseded slot", () => {
    // Simulate the race: device B holds T_old, /register handler is mid-await,
    // device A supersedes (T_new is now the live slot). The handler resumes
    // and calls consume — must NOT delete T_new just because the slot exists.
    const tOld = createInviteSlot({ accountId: ACCT_A });
    const tNew = createInviteSlot({ accountId: ACCT_A });

    expect(consumeInviteSlotIfTokenMatches(ACCT_A, tOld.token)).toBeNull();
    // The new (valid) slot is still in place — user with T_new can still
    // complete their ceremony.
    expect(findInviteByToken(tNew.token)?.token).toBe(tNew.token);
  });

  it("consumeInviteSlotIfTokenMatches deletes when the token matches", () => {
    const slot = createInviteSlot({ accountId: ACCT_A });
    const consumed = consumeInviteSlotIfTokenMatches(ACCT_A, slot.token);
    expect(consumed?.token).toBe(slot.token);
    expect(findInviteForAccount(ACCT_A)).toBeNull();
    // Re-running is a no-op, not a re-fetch of stale state.
    expect(consumeInviteSlotIfTokenMatches(ACCT_A, slot.token)).toBeNull();
  });
});
