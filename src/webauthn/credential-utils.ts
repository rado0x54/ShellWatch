import { sha256Fingerprint } from "./fingerprint.js";

/** Detect algorithm from COSE key (first bytes of the map) */
export function detectAlgorithm(coseKey: Buffer): string {
  // COSE alg field (label 3): -7 = ES256 (P-256), -8 = EdDSA (Ed25519)
  if (coseKey.includes(Buffer.from([0x03, 0x26]))) return "ES256 (P-256)";
  if (coseKey.includes(Buffer.from([0x03, 0x27]))) return "EdDSA (Ed25519)";
  return "unknown";
}

/** Compute OpenSSH-style SHA-256 fingerprint of the COSE public key */
export function computeFingerprint(coseKey: Buffer): string {
  return sha256Fingerprint(coseKey);
}
