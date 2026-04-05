/**
 * WebSocket endpoint that bridges the SSH agent protocol for remote clients.
 *
 * A thin Go client on the user's workstation connects here via WSS,
 * relaying SSH agent protocol frames from the local Unix socket.
 * Each binary WebSocket message is one complete agent protocol frame
 * (4-byte BE length prefix + payload).
 */

import type { FastifyInstance } from "fastify";
import type { WebSocket } from "ws";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import type { ApiKeyRepository } from "../db/repositories/api-key-repo.js";
import type { PrivateKeyProvider } from "../transport/key-directory-watcher.js";
import type { ScannedKey } from "../transport/key-scanner.js";
import type { SigningBridge } from "../webauthn/signing-bridge.js";
import { hashApiKey } from "../server/auth/api-key-auth.js";
import { createAgentHandler } from "./socket-agent-handler.js";

export interface AgentProxyRouteParams {
  app: FastifyInstance;
  basePath: string;
  keyProvider: PrivateKeyProvider & { getAvailableKeys(): ScannedKey[] };
  apiKeyRepo: ApiKeyRepository;
  accountRepo: AccountRepository;
  /** Signing bridge for WebAuthn passkey support through the agent proxy */
  signingBridge?: SigningBridge;
  /** Look up passkeys for an account */
  findCredentialsForAccount?: (accountId: string) => WebAuthnCredentialInfo[];
  /** WebAuthn relying party ID */
  rpId: string;
}

export function registerAgentProxyRoute(params: AgentProxyRouteParams): void {
  const {
    app,
    basePath,
    keyProvider,
    apiKeyRepo,
    accountRepo,
    signingBridge,
    findCredentialsForAccount,
    rpId,
  } = params;

  app.get(`${basePath}/agent-proxy`, { websocket: true }, async (socket: WebSocket, request) => {
    // Authenticate via API key
    const auth = request.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
      socket.close(4001, "API key required");
      return;
    }

    const token = auth.slice(7);
    const hash = hashApiKey(token);
    const key = await apiKeyRepo.findByHash(hash);

    if (!key) {
      socket.close(4001, "Invalid API key");
      return;
    }

    if (!key.scopes.includes("agent")) {
      socket.close(4003, "API key lacks 'agent' scope");
      return;
    }

    // Touch last-used timestamp
    accountRepo.touchLastUsed(key.accountId);

    const logger = {
      error: (msg: string) => app.log.error(msg),
      debug: (msg: string) => app.log.debug(msg),
    };

    // Look up passkeys for the authenticated account
    const passkeys = findCredentialsForAccount?.(key.accountId) ?? [];

    const { protocol, cleanup } = createAgentHandler({
      keyProvider,
      logger,
      passkeys,
      signingBridge,
      rpId,
    });

    app.log.info(`Agent proxy connected (account: ${key.accountId}, key: ${key.keyPrefix}...)`);

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
