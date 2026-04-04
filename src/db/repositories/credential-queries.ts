import { count, eq } from "drizzle-orm";
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
