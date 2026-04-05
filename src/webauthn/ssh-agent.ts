/**
 * Custom ssh2 agent that delegates signing to the browser via WebAuthn.
 *
 * Supports single-passkey mode (assigned, direct sign) and multi-passkey mode
 * (auto-negotiate with signing confirmation modal).
 *
 * When ssh2 needs to authenticate with a WebAuthn key:
 * 1. getIdentities() returns the registered WebAuthn public keys
 * 2. sign() sends the SSH challenge to the browser via a callback
 * 3. The browser calls navigator.credentials.get() — user touches YubiKey
 * 4. The browser returns the WebAuthn assertion
 * 5. We wrap it in the webauthn-sk-ecdsa SSH signature wire format
 * 6. Return to ssh2 via the callback
 */

import ssh2 from "ssh2";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import { buildSshSignatureBlob, parseWebAuthnSignature } from "./signature-format.js";
import { buildPublicKeyBlob } from "./ssh-key-format.js";

// BaseAgent is exported by ssh2 but not in the type definitions
const BaseAgent = (ssh2 as Record<string, unknown>).BaseAgent as new () => Record<string, unknown>;

export { BaseAgent };

/**
 * ssh2 parses key blobs from getIdentities() into key objects before passing
 * them to sign(). Extract the raw public key blob for comparison.
 */
export function toPublicKeyBlob(pubKey: Buffer | { getPublicSSH?: () => Buffer }): Buffer {
  if (Buffer.isBuffer(pubKey)) return pubKey;
  if (typeof pubKey === "object" && pubKey && "getPublicSSH" in pubKey) {
    return (pubKey as { getPublicSSH: () => Buffer }).getPublicSSH();
  }
  throw new Error(`Unexpected public key type: ${typeof pubKey}`);
}

export interface PasskeyEntry {
  /** Raw public key blob (from buildPublicKeyBlob()) */
  publicKeyBlob: Buffer;
  /** WebAuthn credential info */
  credential: WebAuthnCredentialInfo;
}

/** Build a PasskeyEntry from a WebAuthn credential. Returns null if the credential lacks an OpenSSH public key. */
export function buildPasskeyEntry(credential: WebAuthnCredentialInfo): PasskeyEntry | null {
  if (!credential.publicKeyOpenSsh) return null;
  return {
    publicKeyBlob: buildPublicKeyBlob({ publicKey: credential.publicKeyOpenSsh }),
    credential,
  };
}

export interface SignRequest {
  requestId: string;
  credentialId: string;
  dataToSign: Buffer;
  rpId: string;
  /** Endpoint label for the signing modal (present in auto-negotiate mode) */
  endpointLabel?: string;
  /** Endpoint address (user@host:port) for the signing modal */
  endpointAddress?: string;
  /** Passkey label for the signing modal */
  passkeyLabel?: string;
}

export interface SignResponse {
  requestId: string;
  authenticatorData: Buffer;
  signature: Buffer;
  clientDataJSON: string;
}

type SignRequestCallback = (request: SignRequest) => void;

export interface AgentLogger {
  error(msg: string): void;
}

export interface WebAuthnSshAgentParams {
  passkeys: PasskeyEntry[];
  rpId: string;
  onSignRequest: SignRequestCallback;
  /** When set, sign requests include endpoint context (triggers signing modal on client) */
  endpointLabel?: string;
  /** Endpoint address for modal display */
  endpointAddress?: string;
  logger?: AgentLogger;
}

/**
 * A custom ssh2 agent backed by WebAuthn credentials.
 * The actual signing happens in the browser — this agent bridges the gap.
 *
 * Supports both single-passkey (direct sign, no modal) and multi-passkey
 * (auto-negotiate with signing confirmation modal) modes.
 */
export class WebAuthnSshAgent extends BaseAgent {
  protected pendingSign: Map<
    string,
    { cb: (err: Error | null, signature?: Buffer) => void; timeout: ReturnType<typeof setTimeout> }
  > = new Map();
  protected onSignRequest: SignRequestCallback;
  protected passkeys: PasskeyEntry[];
  protected rpId: string;
  protected endpointLabel?: string;
  protected endpointAddress?: string;
  protected log: AgentLogger;

  constructor(params: WebAuthnSshAgentParams) {
    super();
    this.passkeys = params.passkeys;
    this.rpId = params.rpId;
    this.onSignRequest = params.onSignRequest;
    this.endpointLabel = params.endpointLabel;
    this.endpointAddress = params.endpointAddress;
    this.log = params.logger ?? { error: (msg) => process.stderr.write(`${msg}\n`) };
  }

  /**
   * Called by ssh2 to get available identities (public keys).
   */
  getIdentities(cb: (err: Error | null, keys?: Buffer[]) => void): void {
    try {
      const keys = this.passkeys.map((pk) => pk.publicKeyBlob);
      cb(null, keys);
    } catch (err) {
      this.log.error(`[WebAuthn Agent] getIdentities error: ${(err as Error).message}`);
      cb(err as Error);
    }
  }

  /**
   * Called by ssh2 when it needs a signature.
   * Matches the public key to the correct passkey and forwards to the browser.
   */
  sign(
    pubKey: Buffer,
    data: Buffer,
    _options: unknown,
    cb: (err: Error | null, signature?: Buffer) => void,
  ): void {
    const pubKeyBlob = toPublicKeyBlob(pubKey);
    const passkey = this.passkeys.find((pk) => pk.publicKeyBlob.equals(pubKeyBlob));
    if (!passkey) {
      cb(new Error("No matching passkey found for signing"));
      return;
    }

    const requestId = `sign_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    const timeout = setTimeout(() => {
      this.log.error(`[WebAuthn Agent] Signing timed out for ${requestId}`);
      this.pendingSign.delete(requestId);
      cb(new Error("WebAuthn signing timed out — no response from browser"));
    }, 60_000);

    this.pendingSign.set(requestId, { cb, timeout });

    this.onSignRequest({
      requestId,
      credentialId: passkey.credential.credentialId,
      dataToSign: data,
      rpId: this.rpId,
      ...(this.endpointLabel && {
        endpointLabel: this.endpointLabel,
        endpointAddress: this.endpointAddress,
        passkeyLabel: passkey.credential.label,
      }),
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
      this.log.error(`[WebAuthn Agent] Signature build error: ${(err as Error).message}`);
      pending.cb(err as Error);
    }
  }

  /**
   * Called when the browser reports a signing error.
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
