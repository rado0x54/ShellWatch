/**
 * Shared handler logic for SSH agent protocol connections.
 *
 * Creates an AgentProtocol (server mode) and delegates identity/sign
 * requests to a CompositeSshAgent built from current file keys and passkeys.
 *
 * Passkeys require OpenSSH 10.3+ on the client. Sign requests are routed
 * through the PendingAction system — the user approves via the signing
 * view, which can be reached from any notification channel (WebSocket toast,
 * Web Push, etc.).
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
} from "../webauthn/index.js";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import type { SigningBridge } from "../webauthn/signing-bridge.js";
import type { AgentProxyContext } from "../pending-action/types.js";

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
  /** Passkey credentials for the authenticated account (empty if none) */
  passkeys?: WebAuthnCredentialInfo[];
  /** Signing bridge for creating PendingActions from sign requests */
  signingBridge?: SigningBridge;
  /** Relying party ID for WebAuthn (e.g. "localhost") */
  rpId: string;
  /** Account ID for the authenticated connection */
  accountId: string;
  /** Source IP of the connecting client */
  sourceIp: string;
  /** API key prefix for display context */
  apiKeyPrefix: string;
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

  const agent = buildAgent(deps);

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
 * Passkeys are always included when available — sign requests are routed
 * through the PendingAction system which handles notification delivery
 * regardless of whether a browser is currently connected.
 */
function buildAgent(deps: AgentHandlerDeps): CompositeSshAgent {
  const { keyProvider, logger, signingBridge, rpId, accountId, sourceIp, apiKeyPrefix } = deps;

  const availableKeys = keyProvider.getAvailableKeys();
  const fileKeyEntries = availableKeys
    .map((k) => buildFileKeyEntry(k.privateKeyContent))
    .filter((e) => e !== null);

  // Always include passkeys — sign requests go through PendingAction notification
  const passkeyEntries: PasskeyEntry[] = [];
  if (deps.passkeys) {
    for (const cred of deps.passkeys) {
      const entry = buildPasskeyEntry(cred);
      if (entry) passkeyEntries.push(entry);
    }
  }

  const debug = logger?.debug ?? (() => {});
  debug(
    `[Agent Proxy] building agent: ${fileKeyEntries.length} file key(s), ${passkeyEntries.length} passkey(s)`,
  );

  const context: AgentProxyContext = {
    source: "agent-proxy",
    sourceIp,
    apiKeyPrefix,
  };

  const onSignRequest = (request: SignRequest) => {
    if (signingBridge) {
      debug(`[Agent Proxy] forwarding sign request to PendingAction system`);
      signingBridge.handleSignRequest(request, accountId, context);
    } else {
      request.reject(new Error("No signing bridge configured"));
    }
  };

  return new CompositeSshAgent({
    passkeys: passkeyEntries,
    fileKeys: fileKeyEntries,
    rpId,
    onSignRequest,
    logger,
  });
}
