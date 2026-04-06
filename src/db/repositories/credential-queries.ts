import { and, count, eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { webauthnCredentials } from "../schema.js";

/** Check if any passkeys are registered in the system. */
export function hasPasskeys(db: ShellWatchDB): boolean {
  const result = db.select({ total: count() }).from(webauthnCredentials).get();
  return (result?.total ?? 0) > 0;
}

export interface WebAuthnCredentialInfo {
  id: string;
  accountId: string;
  credentialId: string;
  label: string;
  publicKeyOpenSsh: string | null;
  revoked: boolean;
}

/** Find all non-revoked WebAuthn credentials for an account (for composite agent). */
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
      and(eq(webauthnCredentials.accountId, accountId), eq(webauthnCredentials.revoked, false)),
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

/** Look up a WebAuthn credential by its ID (for transport factory). */
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
    .where(eq(webauthnCredentials.id, id))
    .get();
  return row ?? null;
}
