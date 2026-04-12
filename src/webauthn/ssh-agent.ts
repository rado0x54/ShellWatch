/**
 * Custom ssh2 agent that delegates signing via WebAuthn.
 *
 * When ssh2 needs to authenticate with a WebAuthn key:
 * 1. getIdentities() returns the registered WebAuthn public keys
 * 2. sign() fires the onSignRequest callback with the challenge + resolve/reject
 * 3. The external coordinator (PendingActionStore) manages the lifecycle
 * 4. When resolved, the coordinator calls resolve(SignResponse)
 * 5. The agent builds the SSH signature blob and completes the ssh2 callback
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
  credentialId: string;
  dataToSign: Buffer;
  rpId: string;
  passkeyLabel?: string;
  /** Endpoint label (present when endpoint context is known) */
  endpointLabel?: string;
  /** Endpoint address (user@host:port) */
  endpointAddress?: string;
  /** Resolve the ssh2 sign callback with a WebAuthn assertion */
  resolve: (result: SignResponse) => void;
  /** Reject the ssh2 sign callback with an error */
  reject: (error: Error) => void;
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
  /** When set, sign requests include endpoint context */
  endpointLabel?: string;
  /** Endpoint address for display */
  endpointAddress?: string;
  logger?: AgentLogger;
}

/**
 * A custom ssh2 agent backed by WebAuthn credentials.
 * The actual signing happens externally — this agent bridges the gap.
 *
 * Sign lifecycle (pending state, timeouts) is managed by the external
 * coordinator via the resolve/reject callbacks on SignRequest.
 */
export class WebAuthnSshAgent extends BaseAgent {
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
   * Matches the public key to the correct passkey and delegates to
   * the onSignRequest callback with resolve/reject closures that
   * convert a WebAuthn assertion into an SSH signature blob.
   */
  sign(
    pubKey: Buffer,
    data: Buffer,
    options: unknown,
    cb: (err: Error | null, signature?: Buffer) => void,
  ): void {
    this.signPasskeyWithCallback(pubKey, data, options, cb, this.onSignRequest);
  }

  /**
   * Core passkey sign routine; takes an explicit sign-request callback so that
   * subclasses (e.g. ForwardingAgent) can route forwarded channel sign requests
   * through a different callback than the one used for ShellWatch's own auth.
   */
  protected signPasskeyWithCallback(
    pubKey: Buffer,
    data: Buffer,
    _options: unknown,
    cb: (err: Error | null, signature?: Buffer) => void,
    signRequestCallback: SignRequestCallback,
  ): void {
    const pubKeyBlob = toPublicKeyBlob(pubKey);
    const passkey = this.passkeys.find((pk) => pk.publicKeyBlob.equals(pubKeyBlob));
    if (!passkey) {
      cb(new Error("No matching passkey found for signing"));
      return;
    }

    const resolve = (response: SignResponse) => {
      try {
        const { r, s, flags, counter } = parseWebAuthnSignature(
          response.authenticatorData,
          response.signature,
        );
        const signatureBlob = buildSshSignatureBlob(r, s, flags, counter, response.clientDataJSON);
        cb(null, signatureBlob);
      } catch (err) {
        this.log.error(`[WebAuthn Agent] Signature build error: ${(err as Error).message}`);
        cb(err as Error);
      }
    };

    const reject = (error: Error) => {
      cb(error);
    };

    signRequestCallback({
      credentialId: passkey.credential.credentialId,
      dataToSign: data,
      rpId: this.rpId,
      passkeyLabel: passkey.credential.label,
      endpointLabel: this.endpointLabel,
      endpointAddress: this.endpointAddress,
      resolve,
      reject,
    });
  }

  destroy(): void {
    // No-op — lifecycle is managed by PendingActionStore
  }
}
