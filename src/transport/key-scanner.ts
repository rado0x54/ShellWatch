import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import ssh2 from "ssh2";

const { utils } = ssh2;

export interface ScannedKey {
  /** Filename (e.g., "dev-local.pem") */
  filename: string;
  /** Full file path */
  path: string;
  /** Key type (e.g., "ssh-ed25519", "ssh-rsa") */
  type: string;
  /** Public key in OpenSSH format (e.g., "ssh-ed25519 AAAA...") */
  publicKeyOpenSsh: string;
  /** SHA256 fingerprint of the public key */
  fingerprint: string;
  /** Raw private key content */
  privateKeyContent: string;
}

/**
 * Scan a directory for SSH private key files.
 * Reads all .pem files, extracts public keys and fingerprints.
 */
export function scanKeyDirectory(directory: string): ScannedKey[] {
  const keys: ScannedKey[] = [];

  let files: string[];
  try {
    files = readdirSync(directory);
  } catch {
    return [];
  }

  for (const filename of files) {
    // Only process .pem files (skip .pub files and others)
    if (!filename.endsWith(".pem")) continue;

    const filePath = join(directory, filename);
    try {
      const content = readFileSync(filePath, "utf-8");
      const parsed = utils.parseKey(content);
      if (!parsed || parsed instanceof Error) continue;

      const pubKeyBuf = parsed.getPublicSSH();
      const pubKeyBase64 = pubKeyBuf.toString("base64");
      const fingerprint = `SHA256:${createHash("sha256").update(pubKeyBuf).digest("base64url")}`;
      const publicKeyOpenSsh = `${parsed.type} ${pubKeyBase64}`;

      keys.push({
        filename,
        path: filePath,
        type: parsed.type,
        publicKeyOpenSsh,
        fingerprint,
        privateKeyContent: content,
      });
    } catch {
      // Skip files that can't be parsed as SSH keys
    }
  }

  return keys;
}

/**
 * In-memory key store that maps fingerprints to private key content.
 * Used by SshAuthProvider to find the right key at connection time.
 */
export class KeyStore {
  private byFingerprint = new Map<string, ScannedKey>();

  constructor(keys: ScannedKey[]) {
    for (const key of keys) {
      this.byFingerprint.set(key.fingerprint, key);
    }
  }

  /** Find a key by its fingerprint */
  findByFingerprint(fingerprint: string): ScannedKey | undefined {
    return this.byFingerprint.get(fingerprint);
  }

  /** Get all scanned keys */
  all(): ScannedKey[] {
    return Array.from(this.byFingerprint.values());
  }
}
