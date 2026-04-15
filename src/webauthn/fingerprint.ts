import { createHash } from "node:crypto";

/**
 * Compute an OpenSSH-style SHA256 fingerprint: `SHA256:<base64-no-padding>`.
 * Matches the output of `ssh-keygen -lf` and `ssh-add -l` (standard base64
 * alphabet with `+`/`/`, trailing `=` stripped).
 */
export function sha256Fingerprint(data: Buffer): string {
  const b64 = createHash("sha256").update(data).digest("base64").replace(/=+$/, "");
  return `SHA256:${b64}`;
}
