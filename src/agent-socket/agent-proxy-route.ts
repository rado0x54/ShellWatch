// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * WebSocket endpoint that bridges the SSH agent protocol for remote clients.
 *
 * A thin Go client on the user's workstation connects here via WSS,
 * relaying SSH agent protocol frames from the local Unix socket.
 * Each binary WebSocket message is one complete agent protocol frame
 * (4-byte BE length prefix + payload).
 */

import type { FastifyInstance, FastifyRequest } from "fastify";
import type { WebSocket } from "ws";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import type { PrivateKeyProvider } from "../transport/key-directory-watcher.js";
import type { ScannedKey } from "../transport/key-scanner.js";
import type { SigningBridge } from "../webauthn/signing-bridge.js";
import { sanitizeClientReportedValue } from "../util/sanitize-client-info.js";
import { createAgentHandler } from "./socket-agent-handler.js";

/**
 * Read and sanitize a client-reported handshake header.
 *
 * These values are advertised by the agent client (`X-ShellWatch-Hostname`,
 * `-OS`, `-Version`) and are rendered as "self-reported" in the approval UI.
 * Header lookup is by lowercased name (Fastify/Node HTTP normalize to lower);
 * sanitization (control-char strip + length clamp) is shared with the MCP
 * initialize-handshake path via sanitizeClientReportedValue.
 */
export function readClientHeader(
  request: Pick<FastifyRequest, "headers">,
  lowercaseName: string,
): string | undefined {
  return sanitizeClientReportedValue(request.headers[lowercaseName]);
}

export interface AgentProxyRouteParams {
  app: FastifyInstance;
  keyProvider: PrivateKeyProvider & { getAvailableKeys(): ScannedKey[] };
  /** Signing bridge for routing WebAuthn sign requests through PendingAction */
  signingBridge?: SigningBridge;
  /** Look up passkeys for an account */
  findCredentialsForAccount?: (accountId: string) => WebAuthnCredentialInfo[];
  /** WebAuthn relying party ID */
  rpId: string;
}

export function registerAgentProxyRoute(params: AgentProxyRouteParams): void {
  const { app, keyProvider, signingBridge, findCredentialsForAccount, rpId } = params;

  app.get("/agent-proxy", { websocket: true }, async (socket: WebSocket, request) => {
    // Bearer-gate authenticated this request pre-upgrade and populated
    // request.accountId + request.apiKey (with `agent` scope verified).
    const key = request.apiKey;
    if (!key) {
      // Defensive — should never happen since the gate sets it before the upgrade.
      socket.close(1011, "Internal authentication state missing");
      return;
    }

    const logger = {
      error: (msg: string) => app.log.error(msg),
      debug: (msg: string) => app.log.debug(msg),
    };

    // Look up passkeys for the authenticated account
    const passkeys = findCredentialsForAccount?.(key.accountId) ?? [];

    // Best-effort client metadata from WS handshake headers; see readClientHeader
    // for the sanitization contract. Older clients that don't send these headers
    // simply produce `undefined` values and the UI hides them.
    const clientHostname = readClientHeader(request, "x-shellwatch-hostname");
    const clientOs = readClientHeader(request, "x-shellwatch-os");
    const clientVersion = readClientHeader(request, "x-shellwatch-version");

    const { protocol, cleanup } = createAgentHandler({
      keyProvider,
      logger,
      passkeys,
      signingBridge,
      rpId,
      accountId: key.accountId,
      sourceIp: request.ip,
      clientHostname,
      clientOs,
      clientVersion,
    });

    app.log.info(`Agent proxy connected (account: ${key.accountId})`);

    // Wire WebSocket ↔ AgentProtocol
    // Incoming: binary WS messages → write to protocol stream
    socket.on("message", (data: Buffer | ArrayBuffer | Buffer[], isBinary: boolean) => {
      if (!isBinary) {
        socket.close(4002, "Only binary messages are accepted");
        return;
      }
      const buf = Array.isArray(data)
        ? Buffer.concat(data)
        : Buffer.isBuffer(data)
          ? data
          : Buffer.from(data as ArrayBuffer);
      protocol.write(buf);
    });

    // Outgoing: protocol stream → send as binary WS message
    protocol.on("data", (chunk: Buffer) => {
      if (socket.readyState === socket.OPEN) {
        socket.send(chunk);
      }
    });

    // Cleanup on disconnect
    socket.on("close", () => {
      app.log.info(`Agent proxy disconnected (account: ${key.accountId})`);
      cleanup();
      protocol.destroy();
    });

    socket.on("error", (err) => {
      app.log.error(`Agent proxy error: ${err.message}`);
      cleanup();
      protocol.destroy();
    });

    protocol.on("error", (err: Error) => {
      app.log.error(`Agent protocol error: ${err.message}`);
      socket.close(4000, "Protocol error");
    });
  });
}
