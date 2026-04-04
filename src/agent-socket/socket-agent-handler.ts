/**
 * Shared handler logic for SSH agent protocol connections.
 *
 * Creates an AgentProtocol (server mode) and delegates identity/sign
 * requests to a CompositeSshAgent built from current file keys.
 *
 * Note: WebAuthn passkeys are intentionally excluded from the agent proxy.
 * OpenSSH internally maps `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` to
 * `sk-ecdsa-sha2-nistp256@openssh.com` (both are KEY_ECDSA_SK), canonicalizing
 * the algorithm in SIGN_REQUEST and USERAUTH_REQUEST. The standard sk-ecdsa
 * verifier on the remote server cannot verify WebAuthn signatures (different
 * signed data format, rpId mismatch). See #36 for details.
 *
 * Used by both the WebSocket agent proxy and the optional local socket server.
 */

import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";
import type { PrivateKeyProvider } from "../transport/key-directory-watcher.js";
import type { ScannedKey } from "../transport/key-scanner.js";
import { buildFileKeyEntry, CompositeSshAgent, type WebAuthnSshAgent } from "../webauthn/index.js";

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
  keyProvider: PrivateKeyProvider & { getAvailableKeys(): ScannedKey[] };
  logger?: { error(msg: string): void };
}

/**
 * Create a server-mode AgentProtocol wired to file-key-only signing.
 * Returns the protocol stream and a cleanup function.
 */
export function createAgentHandler(deps: AgentHandlerDeps): {
  protocol: AgentProtocolInstance;
  cleanup: () => void;
} {
  const protocol = new AgentProtocol(false);

  const agent = buildFileKeyAgent(deps);

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

/** Build a CompositeSshAgent with file keys only (no passkeys). */
function buildFileKeyAgent(deps: AgentHandlerDeps): WebAuthnSshAgent & { destroy(): void } {
  const { keyProvider, logger } = deps;

  const availableKeys = keyProvider.getAvailableKeys();
  const fileKeyEntries = availableKeys
    .map((k) => buildFileKeyEntry(k.privateKeyContent))
    .filter((e) => e !== null);

  return new CompositeSshAgent({
    passkeys: [],
    fileKeys: fileKeyEntries,
    rpId: "",
    onSignRequest: () => {},
    logger,
  });
}
