/**
 * Shared handler logic for SSH agent protocol connections.
 *
 * Creates an AgentProtocol (server mode) and delegates identity/sign
 * requests to a CompositeSshAgent built from current file keys and passkeys.
 *
 * Passkeys require OpenSSH 10.3+ on the client and a browser session connected
 * to ShellWatch for WebAuthn signing. See #36 for the full analysis.
 *
 * ## OpenSSH 10.3 canonicalization
 *
 * OpenSSH canonicalizes `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` to
 * `sk-ecdsa-sha2-nistp256@openssh.com` in SIGN_REQUEST key blobs. Both issues
 * this causes are handled in the ssh2 fork (rado0x54/ssh2#1):
 *
 * - **parseKey** accepts `sk-ecdsa` blobs as WebAuthnSKECDSAKey when the
 *   application field is not `"ssh:"` (web domain = webauthn, `"ssh:"` =
 *   standard FIDO2). getPublicSSH() always returns the `webauthn-` prefixed
 *   blob, so Buffer.equals() comparisons with stored passkey blobs work.
 *
 * - **signReply** uses the correct PROTOCOL.u2f wire format for webauthn
 *   signatures (raw sig bytes after the algorithm string, no extra sshString
 *   wrapper).
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
