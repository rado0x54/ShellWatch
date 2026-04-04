/**
 * Composite SSH agent for admin accounts — extends WebAuthnSshAgent with file-based keys.
 *
 * Inheritance: CompositeSshAgent → WebAuthnSshAgent → BaseAgent
 *
 * File keys are offered first (auto-sign, no user interaction), then passkeys
 * (browser signing with confirmation modal). ssh2 probes keys sequentially
 * via publickey probe (RFC 4252 §7) and only calls sign() for accepted keys.
 *
 * Non-admin accounts use WebAuthnSshAgent directly (passkeys only).
 */

import ssh2 from "ssh2";
import { toPublicKeyBlob, WebAuthnSshAgent, type WebAuthnSshAgentParams } from "./ssh-agent.js";

const { utils } = ssh2;

export interface FileKeyEntry {
  /** Raw public key blob (from parseKey().getPublicSSH()) */
  publicKeyBlob: Buffer;
  /** PEM-encoded private key content */
  privateKey: string;
}

/**
 * Build a FileKeyEntry from a PEM private key string.
 * Uses ssh2's parseKey to extract the public key blob.
 */
export function buildFileKeyEntry(privateKey: string): FileKeyEntry | null {
  const parsed = utils.parseKey(privateKey);
  if (!parsed || parsed instanceof Error) return null;
  return {
    publicKeyBlob: parsed.getPublicSSH(),
    privateKey,
  };
}

export interface CompositeAgentParams extends WebAuthnSshAgentParams {
  fileKeys: FileKeyEntry[];
}

/**
 * Admin-only composite ssh2 agent that adds file-based key signing
 * on top of WebAuthnSshAgent's passkey support.
 *
 * File keys are tried first (auto-sign), then passkeys via the inherited
 * WebAuthn browser signing flow.
 */
export class CompositeSshAgent extends WebAuthnSshAgent {
  private fileKeys: FileKeyEntry[];

  constructor(params: CompositeAgentParams) {
    super(params);
    this.fileKeys = params.fileKeys;
  }

  /**
   * Returns file key blobs first, then passkey blobs from the parent.
   */
  override getIdentities(cb: (err: Error | null, keys?: Buffer[]) => void): void {
    super.getIdentities((err, passkeyBlobs) => {
      if (err) {
        cb(err);
        return;
      }
      const fileKeyBlobs = this.fileKeys.map((fk) => fk.publicKeyBlob);
      cb(null, [...fileKeyBlobs, ...(passkeyBlobs ?? [])]);
    });
  }

  /**
   * Tries file keys first (auto-sign), falls back to passkey signing via super.
   */
  override sign(
    pubKey: Buffer,
    data: Buffer,
    options: unknown,
    cb: (err: Error | null, signature?: Buffer) => void,
  ): void {
    const pubKeyBlob = toPublicKeyBlob(pubKey);
    const fileKey = this.fileKeys.find((fk) => fk.publicKeyBlob.equals(pubKeyBlob));
    if (fileKey) {
      this.signWithFileKey(fileKey, data, options as { hash?: string }, cb);
      return;
    }

    // Not a file key — delegate to WebAuthnSshAgent for passkey signing
    super.sign(pubKey, data, options, cb);
  }

  private signWithFileKey(
    fileKey: FileKeyEntry,
    data: Buffer,
    options: { hash?: string },
    cb: (err: Error | null, signature?: Buffer) => void,
  ): void {
    try {
      const parsed = utils.parseKey(fileKey.privateKey);
      if (!parsed || parsed instanceof Error) {
        cb(new Error(`Failed to parse private key: ${parsed?.message ?? "unknown error"}`));
        return;
      }
      const signature = parsed.sign(data, options.hash);
      if (signature instanceof Error) {
        cb(signature);
        return;
      }
      cb(null, signature);
    } catch (err) {
      this.log.error(`[Composite Agent] File key sign error: ${(err as Error).message}`);
      cb(err as Error);
    }
  }
}
