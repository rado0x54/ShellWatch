/**
 * Bridges WebAuthn signing requests between the SSH agent and browser clients.
 *
 * When an SSH connection needs WebAuthn authentication:
 * 1. The agent calls onSignRequest
 * 2. The bridge forwards it to all connected WebSocket clients as fido:sign-request
 * 3. A browser client performs navigator.credentials.get() and sends fido:sign-response
 * 4. The bridge forwards the response back to the agent
 */

import type { WebSocket } from "ws";
import type { SignRequest, SignResponse, WebAuthnSshAgent } from "./ssh-agent.js";

export class SigningBridge {
  private clients = new Set<WebSocket>();
  private agents = new Map<string, WebAuthnSshAgent>();

  /** Register a WebSocket client that can handle signing requests */
  addClient(ws: WebSocket): void {
    this.clients.add(ws);
  }

  removeClient(ws: WebSocket): void {
    this.clients.delete(ws);
  }

  /** Register an agent's sign request handler */
  handleSignRequest(request: SignRequest): void {
    // IMPORTANT: Use standard base64 (not base64url) — matches what
    // OpenSSH's verifier expects when reconstructing clientDataJSON
    const challenge = request.dataToSign.toString("base64");

    const msg = JSON.stringify({
      type: "fido:sign-request",
      requestId: request.requestId,
      credentialId: request.credentialId,
      challenge,
      rpId: request.rpId,
    });

    // Send to ALL open clients — the most recent browser tab will handle it.
    // Stale connections from HMR/reload may still appear open briefly.
    let sent = false;
    for (const client of this.clients) {
      if (client.readyState === client.OPEN) {
        client.send(msg);
        sent = true;
      }
    }

    if (!sent) {
      // No browser clients — find the agent and report error
      for (const agent of this.agents.values()) {
        agent.handleSignError(
          request.requestId,
          "No browser session available for WebAuthn signing. Open ShellWatch in a browser.",
        );
      }
    }
  }

  /** Handle a signing response from a browser client */
  handleSignResponse(response: SignResponse): void {
    for (const agent of this.agents.values()) {
      agent.handleSignResponse(response);
    }
  }

  /** Handle a signing error from a browser client */
  handleSignError(requestId: string, error: string): void {
    for (const agent of this.agents.values()) {
      agent.handleSignError(requestId, error);
    }
  }

  /** Track an agent so we can route responses to it */
  registerAgent(id: string, agent: WebAuthnSshAgent): void {
    this.agents.set(id, agent);
  }

  unregisterAgent(id: string): void {
    this.agents.delete(id);
  }

  get hasClients(): boolean {
    for (const client of this.clients) {
      if (client.readyState === client.OPEN) return true;
    }
    return false;
  }
}
