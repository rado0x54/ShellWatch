/**
 * Shared handler logic for SSH agent protocol connections.
 *
 * Creates an AgentProtocol (server mode) and delegates identity/sign
 * requests to a CompositeSshAgent built from current file keys and passkeys.
 *
 * Passkeys require OpenSSH 10.3+ on the client and a browser session connected
 * to ShellWatch for WebAuthn signing. See #36 for the full analysis.
 *
 * Used by both the WebSocket agent proxy and the optional local socket server.
 */

import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";
import type { PrivateKeyProvider } from "../transport/key-directory-watcher.js";
import type { ScannedKey } from "../transport/key-scanner.js";
import {
  buildFileKeyEntry,
  buildPasskeyEntry,
  CompositeSshAgent,
  type PasskeyEntry,
  type SignRequest,
  type WebAuthnSshAgent,
} from "../webauthn/index.js";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import type { SigningBridge } from "../webauthn/signing-bridge.js";

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
  logger?: { error(msg: string): void; debug?(msg: string): void };
  /** Passkey credentials for the authenticated account (empty if none or no browser) */
  passkeys?: WebAuthnCredentialInfo[];
  /** Signing bridge for forwarding WebAuthn sign requests to the browser */
  signingBridge?: SigningBridge;
  /** Relying party ID for WebAuthn (e.g. "localhost") */
  rpId?: string;
}

/**
 * Create a server-mode AgentProtocol wired to file key + passkey signing.
 * Returns the protocol stream and a cleanup function.
 */
export function createAgentHandler(deps: AgentHandlerDeps): {
  protocol: AgentProtocolInstance;
  cleanup: () => void;
} {
  const protocol = new AgentProtocol(false);
  const debug = deps.logger?.debug ?? (() => {});

  const { agent, agentId } = buildAgent(deps);

  const { utils } = ssh2;

  // Handle identity requests
  protocol.on("identities", (req) => {
    agent.getIdentities((err, keys) => {
      if (err || !keys) {
        debug("[Agent Proxy] identities request failed");
        protocol.failureReply(req);
        return;
      }
      // AgentProtocol.getIdentitiesReply expects parsed key objects, not raw buffers.
      // Parse each blob via ssh2's parseKey so the protocol can serialize them.
      const parsed = keys
        .map((blob) => utils.parseKey(blob))
        .filter((k): k is ParsedKey => !!k && !(k instanceof Error));
      debug(`[Agent Proxy] identities: returning ${parsed.length} key(s)`);
      protocol.getIdentitiesReply(req, parsed);
    });
  });

  // Handle sign requests
  protocol.on("sign", (req, pubKey, data, flags) => {
    const pubKeyBuf = extractPubKeyBlob(pubKey);
    if (!pubKeyBuf) {
      debug("[Agent Proxy] sign request: could not extract public key blob");
      protocol.failureReply(req);
      return;
    }

    debug(
      `[Agent Proxy] sign request: key=${pubKeyBuf.subarray(0, 20).toString("hex")}… len=${data.length}`,
    );

    agent.sign(pubKeyBuf, data, flags, (err, signature) => {
      if (err || !signature) {
        debug(`[Agent Proxy] sign failed: ${err?.message ?? "no signature"}`);
        protocol.failureReply(req);
        return;
      }
      debug(`[Agent Proxy] sign success: ${signature.length} bytes`);
      protocol.signReply(req, signature);
    });
  });

  const cleanup = () => {
    if (agentId && deps.signingBridge) {
      deps.signingBridge.unregisterAgent(agentId);
    }
    agent.destroy();
  };

  return { protocol, cleanup };
}

// SSH agent protocol constants
const SSH_AGENTC_SIGN_REQUEST = 13;
const SK_ECDSA = "sk-ecdsa-sha2-nistp256@openssh.com";
const WEBAUTHN_SK_ECDSA = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";
const SK_ECDSA_BUF = Buffer.from(SK_ECDSA);
const WEBAUTHN_SK_ECDSA_BUF = Buffer.from(WEBAUTHN_SK_ECDSA);
const ALGO_LEN_DIFF = WEBAUTHN_SK_ECDSA_BUF.length - SK_ECDSA_BUF.length; // 9 bytes

/**
 * Rewrite the algorithm name in SSH agent SIGN_REQUEST frames.
 *
 * OpenSSH 10.3 canonicalizes `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` to
 * `sk-ecdsa-sha2-nistp256@openssh.com` in the public key blob inside
 * SSH_AGENTC_SIGN_REQUEST. Our ssh2 fork's parseKey() only recognizes the
 * `webauthn-` prefixed variant, so it returns an error and AgentProtocol
 * sends SSH_AGENT_FAILURE without ever emitting the `sign` event.
 *
 * This function detects SIGN_REQUEST frames whose key blob starts with
 * `sk-ecdsa-sha2-nistp256@openssh.com` and rewrites the algorithm name to
 * `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`, updating all length fields.
 *
 * Frame layout (all uint32 are big-endian):
 *   [0..3]   uint32  total_payload_length
 *   [4]      byte    message_type (13 = SIGN_REQUEST)
 *   [5..8]   uint32  key_blob_length
 *   [9..12]  uint32  algo_name_length  (inside key_blob)
 *   [13..]   bytes   algo_name
 *   ...      rest of key_blob + data + flags
 */
export function rewriteSkEcdsaSignRequest(frame: Buffer): Buffer {
  // Minimum: 4 (len) + 1 (type) + 4 (key_blob_len) + 4 (algo_len) + algo bytes
  if (frame.length < 13 + SK_ECDSA_BUF.length) return frame;
  if (frame[4] !== SSH_AGENTC_SIGN_REQUEST) return frame;

  const algoLen = frame.readUInt32BE(9);
  if (algoLen !== SK_ECDSA_BUF.length) return frame;

  // Check if the algorithm name matches sk-ecdsa
  const algoSlice = frame.subarray(13, 13 + algoLen);
  if (!algoSlice.equals(SK_ECDSA_BUF)) return frame;

  // Rewrite: build new frame with webauthn- prefix
  // Layout: [0..3] total_len | [4] type | [5..8] key_blob_len | [9..12] algo_len | [13..] algo | rest
  const header = frame.subarray(0, 9); // total_len(4) + type(1) + key_blob_len(4)
  const afterAlgo = frame.subarray(13 + algoLen); // everything after old algo name

  const newFrame = Buffer.alloc(frame.length + ALGO_LEN_DIFF);
  let offset = 0;

  // Copy header (length fields will be updated below)
  header.copy(newFrame, offset);
  offset += header.length; // offset = 9

  // Write new algo_name_length
  newFrame.writeUInt32BE(WEBAUTHN_SK_ECDSA_BUF.length, offset);
  offset += 4; // offset = 13

  // Write new algo_name
  WEBAUTHN_SK_ECDSA_BUF.copy(newFrame, offset);
  offset += WEBAUTHN_SK_ECDSA_BUF.length;

  // Copy the rest (key material + data + flags)
  afterAlgo.copy(newFrame, offset);

  // Update total payload length (bytes 0..3)
  const oldPayloadLen = frame.readUInt32BE(0);
  newFrame.writeUInt32BE(oldPayloadLen + ALGO_LEN_DIFF, 0);

  // Update key_blob_length (bytes 5..8)
  const oldKeyBlobLen = frame.readUInt32BE(5);
  newFrame.writeUInt32BE(oldKeyBlobLen + ALGO_LEN_DIFF, 5);

  return newFrame;
}

function extractPubKeyBlob(pubKey: unknown): Buffer | null {
  if (Buffer.isBuffer(pubKey)) return pubKey;
  if (pubKey && typeof pubKey === "object" && "getPublicSSH" in pubKey) {
    return (pubKey as { getPublicSSH: () => Buffer }).getPublicSSH();
  }
  return null;
}

/**
 * Build a CompositeSshAgent with file keys and (optionally) passkeys.
 * Passkeys require a signing bridge with a connected browser and OpenSSH 10.3+
 * on the client. See #36.
 */
function buildAgent(deps: AgentHandlerDeps): {
  agent: WebAuthnSshAgent & { destroy(): void };
  agentId: string | null;
} {
  const { keyProvider, logger, signingBridge, rpId = "" } = deps;

  const availableKeys = keyProvider.getAvailableKeys();
  const fileKeyEntries = availableKeys
    .map((k) => buildFileKeyEntry(k.privateKeyContent))
    .filter((e) => e !== null);

  // Include passkeys if we have a signing bridge with a connected browser
  const passkeyEntries: PasskeyEntry[] = [];
  if (deps.passkeys && signingBridge?.hasClients) {
    for (const cred of deps.passkeys) {
      const entry = buildPasskeyEntry(cred);
      if (entry) passkeyEntries.push(entry);
    }
  }

  const debug = logger?.debug ?? (() => {});
  debug(
    `[Agent Proxy] building agent: ${fileKeyEntries.length} file key(s), ${passkeyEntries.length} passkey(s)`,
  );

  let agentId: string | null = null;
  let onSignRequest: (request: SignRequest) => void = () => {};

  if (passkeyEntries.length > 0 && signingBridge) {
    agentId = `agent-proxy_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    onSignRequest = (request) => {
      debug(`[Agent Proxy] forwarding sign request ${request.requestId} to browser`);
      signingBridge.handleSignRequest(request);
    };
  }

  const agent = new CompositeSshAgent({
    passkeys: passkeyEntries,
    fileKeys: fileKeyEntries,
    rpId,
    onSignRequest,
    logger,
  });

  if (agentId && signingBridge) {
    signingBridge.registerAgent(agentId, agent);
  }

  return { agent, agentId };
}
