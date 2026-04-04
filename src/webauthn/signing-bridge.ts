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
import type { WsExtension } from "../server/ws-extension.js";
import type { SignRequest, SignResponse, WebAuthnSshAgent } from "./ssh-agent.js";

export class SigningBridge implements WsExtension {
  private clients: WebSocket[] = [];
  private agents = new Map<string, WebAuthnSshAgent>();

  // --- WsExtension implementation ---

  onConnect(socket: WebSocket): void {
    this.clients.push(socket);
  }

  onDisconnect(socket: WebSocket): void {
    const idx = this.clients.indexOf(socket);
    if (idx >= 0) this.clients.splice(idx, 1);
  }

  onMessage(msg: Record<string, unknown>, _socket: WebSocket): boolean {
    if (msg.type === "fido:sign-response") {
      this.handleSignResponse({
        requestId: msg.requestId as string,
        authenticatorData: Buffer.from(msg.authenticatorData as string, "base64url"),
        signature: Buffer.from(msg.signature as string, "base64url"),
        clientDataJSON: msg.clientDataJSON as string,
      });
      return true;
    }
    if (msg.type === "fido:sign-error") {
      this.handleSignError(msg.requestId as string, msg.error as string);
      return true;
    }
    return false;
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

    // Send to the most recently connected client only — multiple clients
    // (e.g. Vite dev proxy + direct browser) would each call
    // navigator.credentials.get(), causing "A request is already pending."
    let sent = false;
    for (let i = this.clients.length - 1; i >= 0; i--) {
      const client = this.clients[i];
      if (client.readyState === client.OPEN) {
        client.send(msg);
        sent = true;
        break;
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
    return this.clients.some((c) => c.readyState === c.OPEN);
  }
}
