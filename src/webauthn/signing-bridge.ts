/**
 * Coordinates WebAuthn signing requests between SSH agents and notification channels.
 *
 * When an SSH connection needs WebAuthn authentication:
 * 1. The agent's sign() fires onSignRequest with resolve/reject callbacks
 * 2. The bridge creates a PendingAction in the store
 * 3. The NotificationDispatcher sends notifications to all channels
 * 4. A client resolves/denies via the REST API → PendingActionStore resolves/rejects
 * 5. The resolve callback builds the SSH signature blob and completes the ssh2 callback
 */

import type { NotificationDispatcher } from "../pending-action/dispatcher.js";
import type { PendingActionStore } from "../pending-action/store.js";
import type { SignRequestContext } from "../pending-action/types.js";
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
   * Handle a sign request from an agent. Creates a PendingAction and
   * dispatches notifications to all configured channels.
   */
  handleSignRequest(request: SignRequest, accountId: string, context: SignRequestContext): void {
    // IMPORTANT: Use standard base64 (not base64url) — matches what
    // OpenSSH's verifier expects when reconstructing clientDataJSON
    const challenge = request.dataToSign.toString("base64");

    const action = this.actionStore.create({
      type: "webauthn-sign",
      accountId,
      context,
      credentialId: request.credentialId,
      challenge,
      rpId: request.rpId,
      passkeyLabel: request.passkeyLabel,
      resolve: request.resolve,
      reject: request.reject,
    });

    this.dispatcher.dispatch(action);
  }
}
