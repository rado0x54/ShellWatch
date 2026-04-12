/**
 * Coordinates signing requests between SSH agents and notification channels.
 *
 * Handles two action types:
 * - webauthn-sign: passkey signing via WebAuthn ceremony in the browser
 * - key-approve: file key signing that requires user approval (approve/deny)
 *
 * In both cases:
 * 1. The agent's sign() fires a callback with resolve/reject closures
 * 2. The bridge creates a PendingAction in the store
 * 3. The NotificationDispatcher sends notifications to all channels
 * 4. A client resolves/denies via the REST API
 * 5. The resolve callback completes the ssh2 sign callback
 */

import type { NotificationDispatcher } from "../pending-action/dispatcher.js";
import type { PendingActionStore } from "../pending-action/store.js";
import type { SignRequestContext } from "../pending-action/types.js";
import type { FileKeySignRequest } from "./composite-ssh-agent.js";
import type { SignRequest } from "./ssh-agent.js";

export interface SigningBridgeParams {
  actionStore: PendingActionStore;
  dispatcher: NotificationDispatcher;
}

export class SigningBridge {
  private actionStore: PendingActionStore;
  private dispatcher: NotificationDispatcher;

  constructor(params: SigningBridgeParams) {
    this.actionStore = params.actionStore;
    this.dispatcher = params.dispatcher;
  }

  /**
   * Handle a passkey sign request. Creates a webauthn-sign PendingAction.
   */
  handleSignRequest(
    request: SignRequest,
    accountId: string,
    context: SignRequestContext,
    redirectTo?: string,
  ): void {
    // IMPORTANT: Use standard base64 (not base64url) — matches what
    // OpenSSH's verifier expects when reconstructing clientDataJSON
    const challenge = request.dataToSign.toString("base64");

    const action = this.actionStore.create({
      type: "webauthn-sign",
      accountId,
      context,
      redirectTo,
      credentialId: request.credentialId,
      challenge,
      rpId: request.rpId,
      passkeyLabel: request.passkeyLabel,
      resolve: request.resolve,
      reject: request.reject,
    });

    this.dispatcher.dispatch(action);
  }

  /**
   * Handle a file key sign request. Creates a key-approve PendingAction.
   * The actual file key signing happens inside the resolve closure when
   * the user clicks "Approve" — the private key never leaves the server.
   */
  handleKeyApproveRequest(
    request: FileKeySignRequest,
    accountId: string,
    context: SignRequestContext,
    redirectTo?: string,
  ): void {
    const action = this.actionStore.create({
      type: "key-approve",
      accountId,
      context,
      redirectTo,
      keyLabel: request.fileKey.label,
      keyFingerprint: request.fileKey.fingerprint,
      resolve: request.resolve,
      reject: request.reject,
    });

    this.dispatcher.dispatch(action);
  }
}
