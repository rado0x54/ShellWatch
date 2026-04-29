import { and, eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { webauthnCredentials } from "../schema.js";

/**
 * Credential lifecycle states. Stored as text in webauthn_credentials.state.
 *
 * - `active`: usable for login, SSH signing, listed as an SSH key.
 * - `pending_confirmation`: registered via a passkey invite from another device,
 *   not yet confirmed by the inviting (already-authenticated) device. Pending
 *   credentials are visible in account settings only — they MUST NOT be
 *   returned by login or SSH-signing lookups.
 */
export const CREDENTIAL_STATE = {
  active: "active",
  pendingConfirmation: "pending_confirmation",
} as const;

export type CredentialState = (typeof CREDENTIAL_STATE)[keyof typeof CREDENTIAL_STATE];

/** Check if any passkeys are registered in the system. */
export function hasPasskeys(db: ShellWatchDB): boolean {
  const row = db.select({ id: webauthnCredentials.id }).from(webauthnCredentials).limit(1).get();
  return row !== undefined;
}

export interface WebAuthnCredentialInfo {
  id: string;
  accountId: string;
  credentialId: string;
  label: string;
  publicKeyOpenSsh: string | null;
  revoked: boolean;
}

/**
 * Find credentials usable for login / SSH signing for an account: non-revoked
 * AND state = active. Pending-confirmation credentials are intentionally excluded
 * — until the inviting device confirms, the new passkey cannot be used for
 * anything (no login, no SSH key copy, no SSH signing).
 */
export function findCredentialsForAccount(
  db: ShellWatchDB,
  accountId: string,
): WebAuthnCredentialInfo[] {
  return db
    .select({
      id: webauthnCredentials.id,
      accountId: webauthnCredentials.accountId,
      credentialId: webauthnCredentials.credentialId,
      label: webauthnCredentials.label,
      publicKeyOpenSsh: webauthnCredentials.publicKeyOpenSsh,
      revoked: webauthnCredentials.revoked,
    })
    .from(webauthnCredentials)
    .where(
      and(
        eq(webauthnCredentials.accountId, accountId),
        eq(webauthnCredentials.revoked, false),
        eq(webauthnCredentials.state, CREDENTIAL_STATE.active),
      ),
    )
    .all();
}

/**
 * Return a unique label for a new passkey within an account.
 * Appends " (2)", " (3)", etc. if the base label already exists.
 */
export function deduplicateLabel(db: ShellWatchDB, accountId: string, baseLabel: string): string {
  const existing = new Set(
    db
      .select({ label: webauthnCredentials.label })
      .from(webauthnCredentials)
      .where(eq(webauthnCredentials.accountId, accountId))
      .all()
      .map((r) => r.label),
  );

  if (!existing.has(baseLabel)) return baseLabel;

  let suffix = 2;
  while (existing.has(`${baseLabel} (${suffix})`)) suffix++;
  return `${baseLabel} (${suffix})`;
}

/**
 * Look up a usable credential by its internal ID — active and non-revoked only.
 * Used by the SSH transport factory; returning a pending credential here would
 * let an unconfirmed passkey sign SSH challenges.
 */
export function findCredentialById(db: ShellWatchDB, id: string): WebAuthnCredentialInfo | null {
  const row = db
    .select({
      id: webauthnCredentials.id,
      accountId: webauthnCredentials.accountId,
      credentialId: webauthnCredentials.credentialId,
      label: webauthnCredentials.label,
      publicKeyOpenSsh: webauthnCredentials.publicKeyOpenSsh,
      revoked: webauthnCredentials.revoked,
    })
    .from(webauthnCredentials)
    .where(
      and(
        eq(webauthnCredentials.id, id),
        eq(webauthnCredentials.revoked, false),
        eq(webauthnCredentials.state, CREDENTIAL_STATE.active),
      ),
    )
    .get();
  return row ?? null;
}
