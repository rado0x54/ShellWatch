/**
 * Convert a WebAuthn ECDSA-P256 COSE public key to the custom
 * webauthn-sk-ecdsa-sha2-nistp256@openssh.com authorized_keys format.
 *
 * Based on the OpenSSH PROTOCOL.u2f specification.
 *
 * Wire format:
 *   string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
 *   string  "nistp256"
 *   string  0x04 || X (32 bytes) || Y (32 bytes)  (uncompressed EC point)
 *   string  application (rp.id, e.g., "localhost")
 */

import { decode as cborDecode } from "cbor-x";

const ALGORITHM = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

/** Write a uint32 big-endian */
function writeUint32(buf: Buffer, offset: number, value: number): void {
  buf.writeUInt32BE(value, offset);
}

/** Encode a string/bytes as SSH wire string (uint32 length + data) */
function sshString(data: string | Buffer): Buffer {
  const payload = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  const buf = Buffer.alloc(4 + payload.length);
  writeUint32(buf, 0, payload.length);
  payload.copy(buf, 4);
  return buf;
}

/**
 * Extract ECDSA P-256 X,Y coordinates from a COSE public key.
 * COSE key map labels: 1=kty, 3=alg, -1=crv, -2=x, -3=y
 */
function extractP256FromCose(coseKey: Buffer): { x: Buffer; y: Buffer } {
  const map = cborDecode(coseKey);

  // COSE labels: -2 = x coordinate, -3 = y coordinate
  // cbor-x may decode as Map (integer keys) or Object (string keys)
  const x = map instanceof Map ? map.get(-2) : (map[-2] ?? map["-2"]);
  const y = map instanceof Map ? map.get(-3) : (map[-3] ?? map["-3"]);

  if (!x || !y) {
    throw new Error("Not an ECDSA P-256 key: missing x or y coordinates");
  }

  return {
    x: Buffer.from(x),
    y: Buffer.from(y),
  };
}

/**
 * Convert a WebAuthn COSE public key to OpenSSH authorized_keys format.
 * Returns the full authorized_keys line.
 */
export function coseToAuthorizedKeys(coseKey: Buffer, rpId: string, comment?: string): string {
  const { x, y } = extractP256FromCose(coseKey);

  // Uncompressed EC point: 0x04 || X || Y
  const ecPoint = Buffer.concat([Buffer.from([0x04]), x, y]);

  // SSH wire format: type || curve || point || application
  const keyBlob = Buffer.concat([
    sshString(ALGORITHM),
    sshString("nistp256"),
    sshString(ecPoint),
    sshString(rpId),
  ]);

  const b64 = keyBlob.toString("base64");
  const suffix = comment ? ` ${comment}` : "";
  return `${ALGORITHM} ${b64}${suffix}`;
}

/**
 * Get the sshd_config line needed to accept this key type.
 */
export function getSshdConfigLine(): string {
  return `PubkeyAcceptedAlgorithms=+${ALGORITHM}`;
}

/**
 * Build the raw SSH public key blob from a SshKeyInfo.
 * This is what the agent returns from getIdentities().
 * ssh2's parseKey() will parse this binary blob into a WebAuthnSKECDSAKey.
 */
export function buildPublicKeyBlob(keyInfo: { publicKey: string }): Buffer {
  // publicKey is in OpenSSH format: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAA..."
  // We need just the base64 blob part, decoded to binary
  const parts = keyInfo.publicKey.split(" ");
  if (parts.length < 2) {
    throw new Error("Invalid public key format");
  }
  return Buffer.from(parts[1], "base64");
}

export { ALGORITHM as WEBAUTHN_SSH_ALGORITHM };
