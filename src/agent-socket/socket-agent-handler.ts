/**
 * Shared handler logic for SSH agent protocol connections.
 *
 * Creates an AgentProtocol (server mode) and delegates identity/sign
 * requests to a CompositeSshAgent built from current file keys + passkeys.
 *
 * Used by both the WebSocket agent proxy and the optional local socket server.
 */

import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import type { PrivateKeyProvider } from "../transport/key-directory-watcher.js";
import type { ScannedKey } from "../transport/key-scanner.js";
import {
  buildFileKeyEntry,
  buildPasskeyEntry,
  CompositeSshAgent,
  type SignRequest,
  type SigningBridge,
  type WebAuthnSshAgent,
} from "../webauthn/index.js";

// AgentProtocol is exported at runtime but not in type definitions
const AgentProtocol = (ssh2 as Record<string, unknown>).AgentProtocol as new (
  isClient: boolean,
) => AgentProtocolInstance;

interface AgentProtocolInstance extends NodeJS.ReadWriteStream {
  getIdentitiesReply(req: unknown, keys: unknown[]): boolean;
  signReply(req: unknown, signature: Buffer): boolean;
  failureReply(req: unknown): boolean;
  on(event: "identities", listener: (req: unknown) => void): this;
  on(
    event: "sign",
    listener: (req: unknown, pubKey: unknown, data: Buffer, flags: { hash?: string }) => void,
  ): this;
  on(event: "data", listener: (chunk: Buffer) => void): this;
  on(event: "error", listener: (err: Error) => void): this;
  on(event: string, listener: (...args: never[]) => void): this;
  destroy(): void;
}

export { AgentProtocol, type AgentProtocolInstance };

export interface AgentHandlerDeps {
  signingBridge: SigningBridge;
  keyProvider: PrivateKeyProvider & { getAvailableKeys(): ScannedKey[] };
  findCredentialsForAccount: (accountId: string) => WebAuthnCredentialInfo[];
  rpId: string;
  accountId: string;
  logger?: { error(msg: string): void };
}

/**
 * Create a server-mode AgentProtocol wired to a CompositeSshAgent.
 * Returns the protocol stream and a cleanup function.
 */
export function createAgentHandler(deps: AgentHandlerDeps): {
  protocol: AgentProtocolInstance;
  cleanup: () => void;
} {
  const protocol = new AgentProtocol(false);

  // Build agent from current keys
  const { agent, agentId } = buildAgentForAccount(deps);

  const { utils } = ssh2;

  // Handle identity requests
  protocol.on("identities", (req) => {
    agent.getIdentities((err, keys) => {
      if (err || !keys) {
        protocol.failureReply(req);
        return;
      }
      // AgentProtocol.getIdentitiesReply expects parsed key objects, not raw buffers.
      // Parse each blob via ssh2's parseKey so the protocol can serialize them.
      const parsed = keys
        .map((blob) => utils.parseKey(blob))
        .filter((k): k is ParsedKey => !!k && !(k instanceof Error));
      protocol.getIdentitiesReply(req, parsed);
    });
  });

  // Handle sign requests
  protocol.on("sign", (req, pubKey, data, flags) => {
    // AgentProtocol parses the key blob — extract it back for matching
    const pubKeyBuf = extractPubKeyBlob(pubKey);
    if (!pubKeyBuf) {
      protocol.failureReply(req);
      return;
    }

    agent.sign(pubKeyBuf, data, flags, (err, signature) => {
      if (err || !signature) {
        protocol.failureReply(req);
        return;
      }
      protocol.signReply(req, signature);
    });
  });

  const cleanup = () => {
    deps.signingBridge.unregisterAgent(agentId);
    agent.destroy();
  };

  return { protocol, cleanup };
}

function extractPubKeyBlob(pubKey: unknown): Buffer | null {
  if (Buffer.isBuffer(pubKey)) return pubKey;
  if (pubKey && typeof pubKey === "object" && "getPublicSSH" in pubKey) {
    return (pubKey as { getPublicSSH: () => Buffer }).getPublicSSH();
  }
  return null;
}

function buildAgentForAccount(deps: AgentHandlerDeps): {
  agent: WebAuthnSshAgent & { destroy(): void };
  agentId: string;
} {
  const { signingBridge, keyProvider, findCredentialsForAccount, accountId, rpId, logger } = deps;

  // Gather file keys
  const availableKeys = keyProvider.getAvailableKeys();
  const fileKeyEntries = availableKeys
    .map((k) => buildFileKeyEntry(k.privateKeyContent))
    .filter((e) => e !== null);

  // Gather passkeys for this account
  const credentials = findCredentialsForAccount(accountId);
  const passkeyEntries = credentials.map((c) => buildPasskeyEntry(c)).filter((e) => e !== null);

  const onSignRequest = (request: SignRequest) => signingBridge.handleSignRequest(request);

  const agent = new CompositeSshAgent({
    passkeys: passkeyEntries,
    fileKeys: fileKeyEntries,
    rpId,
    onSignRequest,
    // Agent proxy sign requests always show the modal since
    // the source is an external SSH client, not ShellWatch itself
    endpointLabel: "External SSH client",
    endpointAddress: "agent-proxy",
    logger,
  });

  const agentId = `proxy_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  signingBridge.registerAgent(agentId, agent);

  return { agent, agentId };
}
