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
import type { SshKeyInfo } from "../db/repositories/key-repo.js";
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

/**
 * A custom ssh2 agent backed by WebAuthn credentials.
 * The actual signing happens in the browser — this agent bridges the gap.
 */
export interface WebAuthnKeyWithCredential extends SshKeyInfo {
  /** The actual WebAuthn credential ID (base64url) — needed for navigator.credentials.get() */
  webauthnCredentialId: string;
}

export class WebAuthnSshAgent extends BaseAgent {
  private pendingSign: Map<
    string,
    { cb: (err: Error | null, signature?: Buffer) => void; timeout: ReturnType<typeof setTimeout> }
  > = new Map();
  private onSignRequest: SignRequestCallback;
  private keys: WebAuthnKeyWithCredential[];
  private rpId: string;

  constructor(keys: WebAuthnKeyWithCredential[], rpId: string, onSignRequest: SignRequestCallback) {
    super();
    this.keys = keys;
    this.rpId = rpId;
    this.onSignRequest = onSignRequest;
  }

  /**
   * Called by ssh2 to get available identities (public keys).
   */
  getIdentities(cb: (err: Error | null, keys?: Buffer[]) => void): void {
    try {
      console.log(`[WebAuthn Agent] getIdentities: ${this.keys.length} key(s)`);
      const keyBlobs = this.keys.map((k) => {
        console.log(`[WebAuthn Agent]   key: ${k.id} (${k.fingerprint})`);
        return buildPublicKeyBlob(k);
      });
      cb(null, keyBlobs);
    } catch (err) {
      console.error("[WebAuthn Agent] getIdentities error:", (err as Error).message);
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
    console.log(`[WebAuthn Agent] sign() called, data length: ${data.length}`);

    const matchingKey = this.findKeyForPubKey(pubKey);
    if (!matchingKey) {
      console.error("[WebAuthn Agent] No matching credential for public key");
      cb(new Error("No matching WebAuthn credential found for public key"));
      return;
    }

    console.log(
      `[WebAuthn Agent] Matched key: ${matchingKey.webauthnCredentialId}, sending to browser...`,
    );

    const requestId = `sign_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    const timeout = setTimeout(() => {
      console.error(`[WebAuthn Agent] Signing timed out for ${requestId}`);
      this.pendingSign.delete(requestId);
      cb(new Error("WebAuthn signing timed out — no response from browser"));
    }, 60_000);

    this.pendingSign.set(requestId, { cb, timeout });

    this.onSignRequest({
      requestId,
      credentialId: matchingKey.webauthnCredentialId,
      dataToSign: data,
      rpId: this.rpId,
    });
  }

  /**
   * Called when the browser returns a WebAuthn assertion.
   */
  handleSignResponse(response: SignResponse): void {
    console.log(`[WebAuthn Agent] Received sign response for ${response.requestId}`);
    const pending = this.pendingSign.get(response.requestId);
    if (!pending) {
      console.error(`[WebAuthn Agent] No pending request for ${response.requestId}`);
      return;
    }

    this.pendingSign.delete(response.requestId);
    clearTimeout(pending.timeout);

    try {
      const { r, s, flags, counter } = parseWebAuthnSignature(
        response.authenticatorData,
        response.signature,
      );

      const signatureBlob = buildSshSignatureBlob(r, s, flags, counter, response.clientDataJSON);
      console.log(
        `[WebAuthn Agent] Signature built: ${signatureBlob.length} bytes, flags=${flags}, counter=${counter}`,
      );
      console.log(`[WebAuthn Agent] Signature hex: ${signatureBlob.toString("hex")}`);
      console.log(`[WebAuthn Agent] R (${r.length} bytes): ${r.toString("hex")}`);
      console.log(`[WebAuthn Agent] S (${s.length} bytes): ${s.toString("hex")}`);
      console.log(`[WebAuthn Agent] clientDataJSON: ${response.clientDataJSON.slice(0, 200)}`);
      pending.cb(null, signatureBlob);
    } catch (err) {
      console.error("[WebAuthn Agent] Signature build error:", (err as Error).message);
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

  private findKeyForPubKey(_pubKey: Buffer): WebAuthnKeyWithCredential | null {
    // For now, return the first key — in practice we'd match by comparing
    // the public key blob. With a single passkey this works fine.
    // TODO: proper matching when multiple passkeys are registered
    if (this.keys.length === 0) return null;
    return this.keys[0];
  }

  destroy(): void {
    for (const [_id, { cb, timeout }] of this.pendingSign) {
      clearTimeout(timeout);
      cb(new Error("Agent destroyed"));
    }
    this.pendingSign.clear();
  }
}
