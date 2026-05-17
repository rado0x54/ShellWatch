// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { and, eq, isNotNull } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { accounts, webauthnCredentials } from "../schema.js";

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

export interface ActiveCredentialWithAccount {
  accountId: string;
  accountName: string;
  credentialId: string;
  credentialLabel: string;
  /** Guaranteed non-null — the query filters out rows where this is missing. */
  publicKeyOpenSsh: string;
  /** Guaranteed non-null — the query filters out rows where this is missing. */
  fingerprint: string;
}

/**
 * All credentials usable for SSH authentication across every account: active,
 * non-revoked, account enabled, and convertible to OpenSSH (`publicKeyOpenSsh`
 * and `fingerprint` both present — the latter is persisted at insert time
 * and via the backfill, so any row with a public-key string should have one).
 * Backs the /demo/authorized-keys lookup; not used for any in-account code
 * path. See src/demo-authorized-keys/.
 */
export function findAllActiveCredentialsWithSshKey(
  db: ShellWatchDB,
): ActiveCredentialWithAccount[] {
  const rows = db
    .select({
      accountId: webauthnCredentials.accountId,
      accountName: accounts.name,
      credentialId: webauthnCredentials.credentialId,
      credentialLabel: webauthnCredentials.label,
      publicKeyOpenSsh: webauthnCredentials.publicKeyOpenSsh,
      fingerprint: webauthnCredentials.fingerprint,
    })
    .from(webauthnCredentials)
    .innerJoin(accounts, eq(accounts.id, webauthnCredentials.accountId))
    .where(
      and(
        eq(webauthnCredentials.revoked, false),
        eq(webauthnCredentials.state, CREDENTIAL_STATE.active),
        eq(accounts.enabled, true),
        isNotNull(webauthnCredentials.publicKeyOpenSsh),
        isNotNull(webauthnCredentials.fingerprint),
      ),
    )
    .all();
  // SQL `IS NOT NULL` filters the rows, but both columns' types are still
  // `string | null` until we narrow. Drop any that somehow slipped through.
  return rows.filter(
    (r): r is ActiveCredentialWithAccount => r.publicKeyOpenSsh !== null && r.fingerprint !== null,
  );
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
