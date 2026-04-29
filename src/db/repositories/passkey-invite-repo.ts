import { randomBytes, randomUUID } from "node:crypto";
import { and, eq, isNull } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { passkeyInvites } from "../schema.js";

/** TTL applied to new invites. Issue #101: short window (1h). */
export const PASSKEY_INVITE_TTL_MS = 60 * 60 * 1000;

export interface PasskeyInviteInfo {
  id: string;
  accountId: string;
  token: string;
  label: string;
  expiresAt: string;
  consumedAt: string | null;
  revokedAt: string | null;
  credentialId: string | null;
  createdAt: string;
}

export type InviteStatus = "pending" | "registered" | "expired" | "revoked";

/** Derive the lifecycle status of an invite from its persisted timestamps. */
export function inviteStatus(invite: PasskeyInviteInfo, now: Date = new Date()): InviteStatus {
  if (invite.revokedAt) return "revoked";
  if (invite.consumedAt) return "registered";
  if (Date.parse(invite.expiresAt) <= now.getTime()) return "expired";
  return "pending";
}

export interface PasskeyInviteRepository {
  create(params: { accountId: string; label: string; ttlMs?: number }): PasskeyInviteInfo;
  findById(id: string): PasskeyInviteInfo | null;
  findByIdForAccount(id: string, accountId: string): PasskeyInviteInfo | null;
  /**
   * Look up by token. Used by the public registration endpoints — callers MUST
   * still validate `inviteStatus` is `pending` before consuming, since the row
   * is returned regardless of expiry/consumption/revocation.
   */
  findByToken(token: string): PasskeyInviteInfo | null;
  listForAccount(accountId: string): PasskeyInviteInfo[];
  /** Atomically mark consumed + attach the new credential row. */
  markConsumed(id: string, credentialId: string): boolean;
  /** Mark revoked. Callers handle any cascading credential revocation. */
  revoke(id: string, accountId: string): boolean;
}

export class DrizzlePasskeyInviteRepository implements PasskeyInviteRepository {
  constructor(private db: ShellWatchDB) {}

  create(params: { accountId: string; label: string; ttlMs?: number }): PasskeyInviteInfo {
    const id = randomUUID();
    // 32 bytes of entropy → 43-char base64url. Cookie/URL-safe; no padding.
    const token = randomBytes(32).toString("base64url");
    const now = Date.now();
    const ttl = params.ttlMs ?? PASSKEY_INVITE_TTL_MS;
    const expiresAt = new Date(now + ttl).toISOString();
    const createdAt = new Date(now).toISOString();

    this.db
      .insert(passkeyInvites)
      .values({
        id,
        accountId: params.accountId,
        token,
        label: params.label,
        expiresAt,
        createdAt,
      })
      .run();

    return {
      id,
      accountId: params.accountId,
      token,
      label: params.label,
      expiresAt,
      consumedAt: null,
      revokedAt: null,
      credentialId: null,
      createdAt,
    };
  }

  findById(id: string): PasskeyInviteInfo | null {
    const row = this.db.select().from(passkeyInvites).where(eq(passkeyInvites.id, id)).get();
    return row ?? null;
  }

  findByIdForAccount(id: string, accountId: string): PasskeyInviteInfo | null {
    const row = this.db
      .select()
      .from(passkeyInvites)
      .where(and(eq(passkeyInvites.id, id), eq(passkeyInvites.accountId, accountId)))
      .get();
    return row ?? null;
  }

  findByToken(token: string): PasskeyInviteInfo | null {
    const row = this.db.select().from(passkeyInvites).where(eq(passkeyInvites.token, token)).get();
    return row ?? null;
  }

  listForAccount(accountId: string): PasskeyInviteInfo[] {
    return this.db
      .select()
      .from(passkeyInvites)
      .where(eq(passkeyInvites.accountId, accountId))
      .all();
  }

  markConsumed(id: string, credentialId: string): boolean {
    // Single-use: refuse to overwrite an existing consumedAt. The WHERE clause
    // makes this race-safe under concurrent register attempts on the same token.
    const result = this.db
      .update(passkeyInvites)
      .set({ consumedAt: new Date().toISOString(), credentialId })
      .where(and(eq(passkeyInvites.id, id), isNull(passkeyInvites.consumedAt)))
      .run();
    return result.changes > 0;
  }

  revoke(id: string, accountId: string): boolean {
    const result = this.db
      .update(passkeyInvites)
      .set({ revokedAt: new Date().toISOString() })
      .where(and(eq(passkeyInvites.id, id), eq(passkeyInvites.accountId, accountId)))
      .run();
    return result.changes > 0;
  }
}
