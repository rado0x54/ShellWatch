// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { createHash } from "node:crypto";
import { buildPublicKeyBlob, toSkPublicKeyBlob } from "./ssh-key-format.js";

/**
 * Compute an OpenSSH-style SHA256 fingerprint: `SHA256:<base64-no-padding>`.
 * Matches the output of `ssh-keygen -lf` and `ssh-add -l` (standard base64
 * alphabet with `+`/`/`, trailing `=` stripped).
 */
export function sha256Fingerprint(data: Buffer): string {
  const b64 = createHash("sha256").update(data).digest("base64").replace(/=+$/, "");
  return `SHA256:${b64}`;
}

/**
 * SHA256 fingerprint for an authorized_keys-format public key string. Returns
 * null when no key is available (e.g. a non-ES256 authenticator). Used both by
 * the credentials list and by the invite-register response so device A and
 * device B see the same string for visual comparison.
 */
export function fingerprintFromAuthorizedKeys(authorizedKeysEntry: string | null): string | null {
  if (!authorizedKeysEntry) return null;
  return sha256Fingerprint(
    toSkPublicKeyBlob(buildPublicKeyBlob({ publicKey: authorizedKeysEntry })),
  );
}
