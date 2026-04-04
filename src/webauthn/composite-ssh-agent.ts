/**
 * Composite SSH agent that offers multiple key sources for auto-negotiation.
 *
 * Combines file-based keys (admin only, auto-sign) and passkeys (browser signing).
 * ssh2 probes each key sequentially via publickey probe (RFC 4252 §7).
 * Only keys accepted by the server trigger sign().
 *
 * File keys: sign automatically using ssh2's parseKey(pem).sign()
 * Passkeys: delegate to browser via onSignRequest callback (with signing modal)
 */

import ssh2 from "ssh2";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import { buildSshSignatureBlob, parseWebAuthnSignature } from "./signature-format.js";
import { buildPublicKeyBlob } from "./ssh-key-format.js";
import type { AgentLogger, SignRequest, SignResponse } from "./ssh-agent.js";

const { utils } = ssh2;

// BaseAgent is exported by ssh2 but not in the type definitions
const BaseAgent = (ssh2 as Record<string, unknown>).BaseAgent as new () => Record<string, unknown>;

export interface FileKeyEntry {
  /** Raw public key blob (from parseKey().getPublicSSH()) */
  publicKeyBlob: Buffer;
  /** PEM-encoded private key content */
  privateKey: string;
}

export interface PasskeyEntry {
  /** Raw public key blob (from buildPublicKeyBlob()) */
  publicKeyBlob: Buffer;
  /** WebAuthn credential info */
  credential: WebAuthnCredentialInfo;
}

export interface CompositeSignRequest extends SignRequest {
  /** Endpoint label for the signing modal */
  endpointLabel: string;
  /** Endpoint address (user@host:port) for the signing modal */
  endpointAddress: string;
  /** Passkey label for the signing modal */
  passkeyLabel: string;
}

type CompositeSignRequestCallback = (request: CompositeSignRequest) => void;

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

/**
 * Build a PasskeyEntry from a WebAuthn credential.
 */
export function buildPasskeyEntry(credential: WebAuthnCredentialInfo): PasskeyEntry | null {
  if (!credential.publicKeyOpenSsh) return null;
  return {
    publicKeyBlob: buildPublicKeyBlob({ publicKey: credential.publicKeyOpenSsh }),
    credential,
  };
}

export interface CompositeAgentParams {
  fileKeys: FileKeyEntry[];
  passkeys: PasskeyEntry[];
  onSignRequest: CompositeSignRequestCallback;
  rpId: string;
  endpointLabel: string;
  endpointAddress: string;
  logger?: AgentLogger;
}

/**
 * A composite ssh2 agent that combines file keys and passkeys.
 * File keys are offered first (auto-sign), then passkeys (browser modal).
 */
export class CompositeSshAgent extends BaseAgent {
  private fileKeys: FileKeyEntry[];
  private passkeys: PasskeyEntry[];
  private onSignRequest: CompositeSignRequestCallback;
  private rpId: string;
  private endpointLabel: string;
  private endpointAddress: string;
  private log: AgentLogger;

  private pendingSign: Map<
    string,
    { cb: (err: Error | null, signature?: Buffer) => void; timeout: ReturnType<typeof setTimeout> }
  > = new Map();

  constructor(params: CompositeAgentParams) {
    super();
    this.fileKeys = params.fileKeys;
    this.passkeys = params.passkeys;
    this.onSignRequest = params.onSignRequest;
    this.rpId = params.rpId;
    this.endpointLabel = params.endpointLabel;
    this.endpointAddress = params.endpointAddress;
    this.log = params.logger ?? { error: (msg) => process.stderr.write(`${msg}\n`) };
  }

  /**
   * Called by ssh2 to get available identities (public keys).
   * File keys first (auto-sign), then passkeys.
   */
  getIdentities(cb: (err: Error | null, keys?: Buffer[]) => void): void {
    try {
      const keys: Buffer[] = [];
      for (const fk of this.fileKeys) {
        keys.push(fk.publicKeyBlob);
      }
      for (const pk of this.passkeys) {
        keys.push(pk.publicKeyBlob);
      }
      cb(null, keys);
    } catch (err) {
      this.log.error(`[Composite Agent] getIdentities error: ${(err as Error).message}`);
      cb(err as Error);
    }
  }

  /**
   * Called by ssh2 when it needs a signature for a key the server accepted.
   * Dispatches to file key auto-sign or passkey browser signing.
   */
  sign(
    pubKey: Buffer,
    data: Buffer,
    options: { hash?: string } | unknown,
    cb: (err: Error | null, signature?: Buffer) => void,
  ): void {
    // Try file keys first — auto-sign with no user interaction
    const fileKey = this.fileKeys.find((fk) => fk.publicKeyBlob.equals(pubKey));
    if (fileKey) {
      this.signWithFileKey(fileKey, data, options as { hash?: string }, cb);
      return;
    }

    // Try passkeys — requires browser interaction
    const passkey = this.passkeys.find((pk) => pk.publicKeyBlob.equals(pubKey));
    if (passkey) {
      this.signWithPasskey(passkey, data, cb);
      return;
    }

    cb(new Error("No matching key found for signing"));
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

  private signWithPasskey(
    passkey: PasskeyEntry,
    data: Buffer,
    cb: (err: Error | null, signature?: Buffer) => void,
  ): void {
    const requestId = `sign_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    const timeout = setTimeout(() => {
      this.log.error(`[Composite Agent] Passkey signing timed out for ${requestId}`);
      this.pendingSign.delete(requestId);
      cb(new Error("WebAuthn signing timed out — no response from browser"));
    }, 60_000);

    this.pendingSign.set(requestId, { cb, timeout });

    this.onSignRequest({
      requestId,
      credentialId: passkey.credential.credentialId,
      dataToSign: data,
      rpId: this.rpId,
      endpointLabel: this.endpointLabel,
      endpointAddress: this.endpointAddress,
      passkeyLabel: passkey.credential.label,
    });
  }

  /**
   * Called when the browser returns a WebAuthn assertion.
   */
  handleSignResponse(response: SignResponse): void {
    const pending = this.pendingSign.get(response.requestId);
    if (!pending) return;

    this.pendingSign.delete(response.requestId);
    clearTimeout(pending.timeout);

    try {
      const { r, s, flags, counter } = parseWebAuthnSignature(
        response.authenticatorData,
        response.signature,
      );

      const signatureBlob = buildSshSignatureBlob(r, s, flags, counter, response.clientDataJSON);
      pending.cb(null, signatureBlob);
    } catch (err) {
      this.log.error(`[Composite Agent] Signature build error: ${(err as Error).message}`);
      pending.cb(err as Error);
    }
  }

  /**
   * Called when the browser reports a signing error or the user skips.
   */
  handleSignError(requestId: string, error: string): void {
    const pending = this.pendingSign.get(requestId);
    if (!pending) return;

    this.pendingSign.delete(requestId);
    clearTimeout(pending.timeout);
    pending.cb(new Error(`WebAuthn signing failed: ${error}`));
  }

  destroy(): void {
    for (const [_id, { cb, timeout }] of this.pendingSign) {
      clearTimeout(timeout);
      cb(new Error("Agent destroyed"));
    }
    this.pendingSign.clear();
  }
}
