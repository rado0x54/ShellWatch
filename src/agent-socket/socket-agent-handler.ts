/**
 * Shared handler logic for SSH agent protocol connections.
 *
 * Creates an AgentProtocol (server mode) and delegates identity/sign
 * requests to a CompositeSshAgent built from current file keys and passkeys.
 *
 * Passkeys require OpenSSH 10.3+ on the client and a browser session connected
 * to ShellWatch for WebAuthn signing. See #36 for the full analysis.
 *
 * ## WebAuthn signature wire format workaround
 *
 * ssh2's AgentProtocol has two issues with webauthn-sk-ecdsa keys coming
 * from OpenSSH 10.3 clients via the agent proxy:
 *
 * **1. parseKey rejects canonicalized algorithm names (INBOUND)**
 *
 * OpenSSH canonicalizes `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` to
 * `sk-ecdsa-sha2-nistp256@openssh.com` in SIGN_REQUEST key blobs. Our ssh2
 * fork's parseKey only recognizes the `webauthn-` prefix, so it rejects the
 * key and sends SSH_AGENT_FAILURE without emitting the `sign` event.
 *
 * Fix: `rewriteSkEcdsaSignRequest()` rewrites the algorithm name in the raw
 * frame before it reaches AgentProtocol.
 *
 * **2. signReply wraps with wrong wire format (OUTBOUND)**
 *
 * ssh2's signReply wraps signatures as `sshString(algo) + sshString(sig)`,
 * but PROTOCOL.u2f requires `sshString(algo) + <raw sig bytes>` for webauthn
 * signatures. The extra string wrapper causes the remote server's sshbuf_froms
 * to consume the entire compound blob as the ECDSA signature sub-buffer,
 * leaving nothing for flags/counter/origin/clientData/extensions.
 * See rado0x54/ssh2#1 (Protocol.js change) for the equivalent fix.
 *
 * Fix: for passkey sign responses, we call `failureReply` to keep the protocol
 * state machine consistent (marking the request as responded), then intercept
 * the FAILURE frame in `interceptResponse()` and swap it with a correctly
 * formatted response built by `buildWebauthnSignResponse()`.
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
  matchesSkKeyBlob,
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
 *
 * Returns:
 * - `protocol` — the AgentProtocol stream (pipe incoming frames in, read outgoing frames out)
 * - `interceptResponse` — **must** be called on every outgoing frame from the protocol
 *   before sending to the client. Swaps FAILURE frames with correctly-formatted webauthn
 *   sign responses when needed. For non-webauthn responses, returns the frame unchanged.
 * - `cleanup` — call on disconnect to unregister from the signing bridge and destroy the agent
 */
export function createAgentHandler(deps: AgentHandlerDeps): {
  protocol: AgentProtocolInstance;
  interceptResponse: (frame: Buffer) => Buffer;
  cleanup: () => void;
} {
  const protocol = new AgentProtocol(false);
  const debug = deps.logger?.debug ?? (() => {});

  const { agent, agentId, passkeyEntries } = buildAgent(deps);

  const { utils } = ssh2;

  // ── WebAuthn sign response queue ──────────────────────────────────
  //
  // When a passkey sign request completes, we can't use signReply because
  // it wraps the signature with an extra sshString that breaks the
  // PROTOCOL.u2f wire format (see module docstring).
  //
  // Instead, we:
  //   1. Build the correctly-formatted response frame
  //   2. Push it onto this queue
  //   3. Call failureReply(req) to keep AgentProtocol's internal state
  //      machine happy — this marks the request as responded and allows
  //      subsequent requests to be processed
  //   4. failureReply emits a FAILURE frame on the protocol's data stream
  //   5. interceptResponse() catches that FAILURE, pops our queued frame,
  //      and returns it instead
  //
  // This keeps the protocol state consistent (no stuck requests) while
  // producing the correct wire format for the SSH client.
  const webauthnResponseQueue: Buffer[] = [];

  /**
   * Intercept outgoing frames from the AgentProtocol stream.
   *
   * For most frames, returns the frame unchanged. When a webauthn sign
   * response is queued, swaps the dummy FAILURE frame (emitted by our
   * failureReply call) with the correctly-formatted webauthn response.
   *
   * The caller MUST use this on every protocol `data` event before
   * sending to the client.
   */
  function interceptResponse(frame: Buffer): Buffer {
    // Check: is this a FAILURE frame (5 bytes: uint32(1) + byte(5)) that
    // we should swap with a queued webauthn response?
    if (webauthnResponseQueue.length > 0 && frame.length === 5 && frame[4] === SSH_AGENT_FAILURE) {
      return webauthnResponseQueue.shift()!;
    }
    return frame;
  }

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

    // Determine if this key is a passkey — affects response wire format
    const isPasskey = passkeyEntries.some((pk) => matchesSkKeyBlob(pk.publicKeyBlob, pubKeyBuf));

    debug(
      `[Agent Proxy] sign request: key=${pubKeyBuf.subarray(0, 20).toString("hex")}… len=${data.length} passkey=${isPasskey}`,
    );

    agent.sign(pubKeyBuf, data, flags, (err, signature) => {
      if (err || !signature) {
        debug(`[Agent Proxy] sign failed: ${err?.message ?? "no signature"}`);
        protocol.failureReply(req);
        return;
      }
      debug(`[Agent Proxy] sign success: ${signature.length} bytes passkey=${isPasskey}`);

      if (isPasskey) {
        // ── Webauthn sign response bypass ─────────────────────────
        //
        // Build the response with correct PROTOCOL.u2f wire format,
        // queue it, then call failureReply to flush the protocol's
        // request queue. interceptResponse() will swap the FAILURE
        // frame with our queued response before it reaches the client.
        const frame = buildWebauthnSignResponse(signature);
        debug(`[Agent Proxy] webauthn response frame: ${frame.length} bytes`);
        webauthnResponseQueue.push(frame);
        protocol.failureReply(req);
      } else {
        // File key — standard format, signReply is correct
        protocol.signReply(req, signature);
      }
    });
  });

  const cleanup = () => {
    if (agentId && deps.signingBridge) {
      deps.signingBridge.unregisterAgent(agentId);
    }
    agent.destroy();
  };

  return { protocol, interceptResponse, cleanup };
}

// ── SSH agent protocol constants ──────────────────────────────────────

const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;
const SSH_AGENT_FAILURE = 5;
const SK_ECDSA = "sk-ecdsa-sha2-nistp256@openssh.com";
const WEBAUTHN_SK_ECDSA = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";
const SK_ECDSA_BUF = Buffer.from(SK_ECDSA);
const WEBAUTHN_SK_ECDSA_BUF = Buffer.from(WEBAUTHN_SK_ECDSA);
const ALGO_LEN_DIFF = WEBAUTHN_SK_ECDSA_BUF.length - SK_ECDSA_BUF.length; // 9 bytes

// ── Helpers ───────────────────────────────────────────────────────────

/** Encode a value as SSH wire string (uint32 length + data) */
function sshString(data: Buffer | string): Buffer {
  const payload = typeof data === "string" ? Buffer.from(data) : data;
  const buf = Buffer.alloc(4 + payload.length);
  buf.writeUInt32BE(payload.length, 0);
  payload.copy(buf, 4);
  return buf;
}

function extractPubKeyBlob(pubKey: unknown): Buffer | null {
  if (Buffer.isBuffer(pubKey)) return pubKey;
  if (pubKey && typeof pubKey === "object" && "getPublicSSH" in pubKey) {
    return (pubKey as { getPublicSSH: () => Buffer }).getPublicSSH();
  }
  return null;
}

// ── Inbound: SIGN_REQUEST algorithm rewrite ───────────────────────────
//
// OpenSSH 10.3 canonicalizes the algorithm name in SIGN_REQUEST key blobs
// from `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` to the shorter
// `sk-ecdsa-sha2-nistp256@openssh.com`. Our ssh2 fork's parseKey() only
// recognizes the `webauthn-` prefixed variant — if it sees `sk-ecdsa`, it
// returns an error and AgentProtocol sends FAILURE without emitting `sign`.
//
// This function rewrites the algorithm name in the raw frame so parseKey
// recognizes it. The rest of the frame (key material, data-to-sign, flags)
// is NOT modified — only the algorithm string and the affected length fields.
//
// Frame layout (all uint32 are big-endian):
//   [0..3]   uint32  total_payload_length
//   [4]      byte    message_type (13 = SIGN_REQUEST)
//   [5..8]   uint32  key_blob_length
//   [9..12]  uint32  algo_name_length  (inside key_blob)
//   [13..]   bytes   algo_name
//   ...      rest of key_blob + data + flags

export function rewriteSkEcdsaSignRequest(frame: Buffer): Buffer {
  if (frame.length < 13 + SK_ECDSA_BUF.length) return frame;
  if (frame[4] !== SSH_AGENTC_SIGN_REQUEST) return frame;

  const algoLen = frame.readUInt32BE(9);
  if (algoLen !== SK_ECDSA_BUF.length) return frame;

  const algoSlice = frame.subarray(13, 13 + algoLen);
  if (!algoSlice.equals(SK_ECDSA_BUF)) return frame;

  // Build new frame: same content but with "webauthn-" prefix on the algo name
  const header = frame.subarray(0, 9);
  const afterAlgo = frame.subarray(13 + algoLen);

  const newFrame = Buffer.alloc(frame.length + ALGO_LEN_DIFF);
  let offset = 0;

  header.copy(newFrame, offset);
  offset += header.length;

  newFrame.writeUInt32BE(WEBAUTHN_SK_ECDSA_BUF.length, offset);
  offset += 4;

  WEBAUTHN_SK_ECDSA_BUF.copy(newFrame, offset);
  offset += WEBAUTHN_SK_ECDSA_BUF.length;

  afterAlgo.copy(newFrame, offset);

  // Update length fields to account for the longer algorithm name
  newFrame.writeUInt32BE(frame.readUInt32BE(0) + ALGO_LEN_DIFF, 0); // total payload
  newFrame.writeUInt32BE(frame.readUInt32BE(5) + ALGO_LEN_DIFF, 5); // key blob

  return newFrame;
}

// ── Outbound: WebAuthn sign response builder ──────────────────────────
//
// ssh2's signReply produces:
//
//   string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
//   string  <entire buildSshSignatureBlob output>
//            ↑ WRONG — extra sshString wrapper
//
// But PROTOCOL.u2f (and what OpenSSH's sshd expects) is:
//
//   string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
//   string  ecdsa_signature  ← only R+S (server reads via sshbuf_froms)
//   byte    flags            ← flat in outer buffer
//   uint32  counter          ← flat in outer buffer
//   string  origin           ← flat in outer buffer
//   string  clientDataJSON   ← flat in outer buffer
//   string  extensions       ← flat in outer buffer
//
// buildSshSignatureBlob() already produces the correct compound format
// (sshString(ecdsaSig) + flags + counter + ...). We just need to write it
// RAW after the algorithm name — no extra sshString wrapper.
//
// See rado0x54/ssh2#1 (Protocol.js change) for the equivalent fix in the
// ssh2 fork's direct-connection code path.

export function buildWebauthnSignResponse(signature: Buffer): Buffer {
  const algoStr = sshString(WEBAUTHN_SK_ECDSA);

  // The "signature" field in the agent response is:
  //   sshString(algo) + <raw sig bytes>
  // (NOT sshString(algo) + sshString(sig) — that's what signReply does wrong)
  const innerLen = algoStr.length + signature.length;

  // Full frame: uint32(payloadLen) + byte(type) + sshString(inner)
  const payloadLen = 1 + 4 + innerLen;
  const frame = Buffer.alloc(4 + payloadLen);
  let offset = 0;

  frame.writeUInt32BE(payloadLen, offset);
  offset += 4;
  frame[offset++] = SSH_AGENT_SIGN_RESPONSE;
  frame.writeUInt32BE(innerLen, offset);
  offset += 4;
  algoStr.copy(frame, offset);
  offset += algoStr.length;
  signature.copy(frame, offset);

  return frame;
}

// ── Agent builder ─────────────────────────────────────────────────────

/**
 * Build a CompositeSshAgent with file keys and (optionally) passkeys.
 * Passkeys require a signing bridge with a connected browser and OpenSSH 10.3+
 * on the client. See #36.
 */
function buildAgent(deps: AgentHandlerDeps): {
  agent: WebAuthnSshAgent & { destroy(): void };
  agentId: string | null;
  passkeyEntries: PasskeyEntry[];
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

  return { agent, agentId, passkeyEntries };
}
