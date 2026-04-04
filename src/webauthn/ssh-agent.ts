/**
 * Custom ssh2 agent that delegates signing to the browser via WebAuthn.
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

export interface SignRequest {
  requestId: string;
  credentialId: string;
  dataToSign: Buffer;
  rpId: string;
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

/**
 * A custom ssh2 agent backed by WebAuthn credentials.
 * The actual signing happens in the browser — this agent bridges the gap.
 */
export class WebAuthnSshAgent extends BaseAgent {
  private pendingSign: Map<
    string,
    { cb: (err: Error | null, signature?: Buffer) => void; timeout: ReturnType<typeof setTimeout> }
  > = new Map();
  private onSignRequest: SignRequestCallback;
  private credential: WebAuthnCredentialInfo;
  private rpId: string;
  private log: AgentLogger;

  constructor(
    credential: WebAuthnCredentialInfo,
    rpId: string,
    onSignRequest: SignRequestCallback,
    logger?: AgentLogger,
  ) {
    super();
    this.credential = credential;
    this.rpId = rpId;
    this.onSignRequest = onSignRequest;
    this.log = logger ?? { error: (msg) => process.stderr.write(`${msg}\n`) };
  }

  /**
   * Called by ssh2 to get available identities (public keys).
   */
  getIdentities(cb: (err: Error | null, keys?: Buffer[]) => void): void {
    try {
      if (!this.credential.publicKeyOpenSsh) {
        cb(new Error("WebAuthn credential has no OpenSSH public key"));
        return;
      }
      const keyBlob = buildPublicKeyBlob({ publicKey: this.credential.publicKeyOpenSsh });
      cb(null, [keyBlob]);
    } catch (err) {
      this.log.error(`[WebAuthn Agent] getIdentities error: ${(err as Error).message}`);
      cb(err as Error);
    }
  }

  /**
   * Called by ssh2 when it needs a signature.
   * We forward the request to the browser and wait for the response.
   */
  sign(
    pubKey: Buffer,
    data: Buffer,
    _options: unknown,
    cb: (err: Error | null, signature?: Buffer) => void,
  ): void {
    const requestId = `sign_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    const timeout = setTimeout(() => {
      this.log.error(`[WebAuthn Agent] Signing timed out for ${requestId}`);
      this.pendingSign.delete(requestId);
      cb(new Error("WebAuthn signing timed out — no response from browser"));
    }, 60_000);

    this.pendingSign.set(requestId, { cb, timeout });

    this.onSignRequest({
      requestId,
      credentialId: this.credential.credentialId,
      dataToSign: data,
      rpId: this.rpId,
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
