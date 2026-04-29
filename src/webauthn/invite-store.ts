import { randomBytes } from "node:crypto";

/**
 * In-memory passkey-invite slot. One slot per account, 5-minute TTL. Creating
 * a new invite for an account that already has one supersedes it (the old
 * token immediately becomes unusable). Consuming the slot via the public
 * registration endpoint drops it from the store; the credential row produced
 * by the consumption is the persisted artifact.
 *
 * Why in-memory: an invite link is short-lived, single-use, and the only
 * reason to recover one across a server restart is so the user doesn't have
 * to re-issue. With a 5-minute TTL the user is just going to re-issue
 * anyway, so the persistence buy-back isn't worth the schema complexity.
 */

const TTL_MS = 5 * 60 * 1000;

export interface InviteSlot {
  accountId: string;
  token: string;
  /**
   * Suggested label, set by the inviter. The actual passkey label is chosen
   * on device B during the registration ceremony — this is only the
   * placeholder rendered on the invite landing page.
   */
  label: string;
  expiresAt: number;
  createdAt: number;
}

export interface CreateInviteParams {
  accountId: string;
  label: string;
  /** Override TTL (used by tests). */
  ttlMs?: number;
}

const byAccount = new Map<string, InviteSlot>();

function isExpired(slot: InviteSlot, now: number): boolean {
  return slot.expiresAt <= now;
}

/**
 * Create or supersede the active invite for an account. Returns the new slot.
 * Any previously-issued token for this account is immediately invalidated by
 * being replaced in the map (token-lookup uses iteration over current values).
 */
export function createInviteSlot(params: CreateInviteParams): InviteSlot {
  const now = Date.now();
  const slot: InviteSlot = {
    accountId: params.accountId,
    token: randomBytes(32).toString("base64url"),
    label: params.label,
    expiresAt: now + (params.ttlMs ?? TTL_MS),
    createdAt: now,
  };
  byAccount.set(params.accountId, slot);
  return slot;
}

/** Return the active invite for an account, or null if none / expired. */
export function findInviteForAccount(accountId: string): InviteSlot | null {
  const slot = byAccount.get(accountId);
  if (!slot) return null;
  if (isExpired(slot, Date.now())) {
    byAccount.delete(accountId);
    return null;
  }
  return slot;
}

/**
 * Look up an active invite by token. Used by the public registration
 * endpoints. O(n) over current slots, but n ≤ active accounts.
 */
export function findInviteByToken(token: string): InviteSlot | null {
  const now = Date.now();
  for (const [accountId, slot] of byAccount) {
    if (isExpired(slot, now)) {
      byAccount.delete(accountId);
      continue;
    }
    if (slot.token === token) return slot;
  }
  return null;
}

/**
 * Consume the slot for an account, removing it. Called once the device-B
 * WebAuthn ceremony has completed and produced a credential row. Returns the
 * removed slot for convenience (or null if it was already gone — caller is
 * responsible for deciding whether that's a race condition).
 */
export function consumeInviteSlot(accountId: string): InviteSlot | null {
  const slot = byAccount.get(accountId);
  if (!slot) return null;
  byAccount.delete(accountId);
  return slot;
}

/** Test helper: drop all slots. */
export function _resetInviteStore(): void {
  byAccount.clear();
}
