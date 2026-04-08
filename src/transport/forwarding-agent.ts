/**
 * Wraps a CompositeSshAgent with a `getStream()` method so ssh2's
 * agent forwarding channel handler can pipe raw agent protocol data
 * through it. Each call to `getStream()` creates a fresh AgentProtocol
 * stream backed by the same underlying agent.
 *
 * ssh2 requires `getStream(cb)` on the agent object to handle incoming
 * `auth-agent@openssh.com` channels (see client.js ~line 1998).
 *
 * ## AgentProtocol bug workaround
 *
 * ssh2's AgentProtocol (server mode) has a bug: the `default` case in
 * the message parser doesn't advance the read position past the message
 * body. When OpenSSH >=8.9 sends `SSH_AGENTC_EXTENSION` (type 27, for
 * `session-bind@openssh.com` hostkey binding), the extension body bytes
 * remain in the parse buffer, corrupting subsequent message parsing.
 *
 * We work around this with `AgentBridgeStream` — a Duplex that parses
 * SSH agent framing on the write side, responds to unknown message types
 * with SSH_AGENT_FAILURE directly, and only forwards known types
 * (REQUEST_IDENTITIES=11, SIGN_REQUEST=13) to the AgentProtocol.
 */

import { Duplex, type DuplexOptions } from "node:stream";
import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";
import type { WebAuthnSshAgent } from "../webauthn/ssh-agent.js";

const { utils } = ssh2;

// BaseAgent is exported at runtime but not in type definitions
const BaseAgent = (ssh2 as Record<string, unknown>).BaseAgent as new () => object;

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

const SSH_AGENTC_REQUEST_IDENTITIES = 11;
const SSH_AGENTC_SIGN_REQUEST = 13;

/** 5-byte pre-built SSH_AGENT_FAILURE response: length=1, type=5 */
const FAILURE_RESPONSE = Buffer.from([0, 0, 0, 1, 5]);

type LogFn = (msg: string) => void;

/**
 * Duplex stream sitting between the SSH channel and AgentProtocol.
 *
 * Write side (channel → here): parses SSH agent framing, filters out
 * unknown message types (responding with SSH_AGENT_FAILURE), forwards
 * known types to AgentProtocol.
 *
 * Read side (here → channel): passes through AgentProtocol output.
 */
class AgentBridgeStream extends Duplex {
  private protocol: AgentProtocolInstance;
  private buf: Buffer | null = null;
  private msgLen = -1;
  private log: LogFn;

  constructor(protocol: AgentProtocolInstance, log: LogFn, opts?: DuplexOptions) {
    super(opts);
    this.protocol = protocol;
    this.log = log;

    // Forward protocol output to the readable side
    protocol.on("data", (chunk: Buffer) => {
      this.push(chunk);
    });
  }

  _write(data: Buffer, _encoding: BufferEncoding, cb: (err?: Error | null) => void): void {
    this.buf = this.buf ? Buffer.concat([this.buf, data]) : data;

    while (this.buf && this.buf.length >= 5) {
      if (this.msgLen === -1) {
        this.msgLen = this.buf.readUInt32BE(0);
      }

      const totalLen = 4 + this.msgLen;
      if (this.buf.length < totalLen) break; // wait for more data

      const msgType = this.buf[4];
      const msgBuf = this.buf.subarray(0, totalLen);

      // Advance buffer past this message
      this.buf = this.buf.length > totalLen ? this.buf.subarray(totalLen) : null;
      this.msgLen = -1;

      if (msgType === SSH_AGENTC_REQUEST_IDENTITIES || msgType === SSH_AGENTC_SIGN_REQUEST) {
        // Known type — forward to AgentProtocol
        this.protocol.write(msgBuf);
      } else {
        // Unknown type (e.g. SSH_AGENTC_EXTENSION=27) — respond with failure
        // directly, bypassing AgentProtocol entirely.
        this.log(`filtered unknown agent message type ${msgType} (${this.msgLen + 1} body bytes)`);
        this.push(FAILURE_RESPONSE);
      }
    }

    cb();
  }

  _read(): void {
    // Data is pushed by the protocol 'data' handler — nothing to pull
  }
}

/**
 * An agent wrapper that delegates identity/sign to a CompositeSshAgent
 * and provides `getStream()` for ssh2's agent forwarding channel handler.
 *
 * Extends BaseAgent so ssh2's `isAgent()` check passes (it uses instanceof).
 */
export class ForwardingAgent extends BaseAgent {
  private protocols: AgentProtocolInstance[] = [];
  private agent: WebAuthnSshAgent;
  private logger?: { error(msg: string): void; debug?(msg: string): void };
  private streamCount = 0;

  constructor(
    agent: WebAuthnSshAgent,
    logger?: { error(msg: string): void; debug?(msg: string): void },
  ) {
    super();
    this.agent = agent;
    this.logger = logger;
  }

  private log(msg: string): void {
    (this.logger?.debug ?? this.logger?.error ?? console.log)(`[ForwardingAgent] ${msg}`);
  }

  /** Required by ssh2's isAgent() check */
  getIdentities(cb: (err: Error | null, keys?: Buffer[]) => void): void {
    this.agent.getIdentities(cb);
  }

  /** Required by ssh2's isAgent() check */
  sign(
    pubKey: Buffer,
    data: Buffer,
    options: { hash?: string } | ((err: Error | null, sig?: Buffer) => void),
    cb?: (err: Error | null, sig?: Buffer) => void,
  ): void {
    if (typeof options === "function") {
      this.agent.sign(pubKey, data, {}, options);
    } else {
      this.agent.sign(pubKey, data, options, cb!);
    }
  }

  /**
   * Called by ssh2 for each incoming `auth-agent@openssh.com` channel.
   * Returns an AgentBridgeStream that filters unknown message types and
   * delegates known ones to a fresh AgentProtocol instance.
   */
  getStream(cb: (err: Error | null, stream?: NodeJS.ReadWriteStream) => void): void {
    const streamId = ++this.streamCount;
    this.log(`getStream() called — stream #${streamId}`);

    const protocol = new AgentProtocol(false); // server mode
    this.protocols.push(protocol);

    const logFn = (msg: string) => this.log(`stream #${streamId}: ${msg}`);

    protocol.on("identities", (req) => {
      this.log(`stream #${streamId}: identities request received`);
      this.agent.getIdentities((err, keys) => {
        if (err || !keys) {
          this.log(`stream #${streamId}: identities failed: ${err?.message ?? "no keys"}`);
          protocol.failureReply(req);
          return;
        }
        const parsed = keys
          .map((blob) => utils.parseKey(blob))
          .filter((k): k is ParsedKey => !!k && !(k instanceof Error));
        this.log(`stream #${streamId}: identities reply — ${parsed.length} key(s)`);
        protocol.getIdentitiesReply(req, parsed);
      });
    });

    protocol.on("sign", (req, pubKey, data, flags) => {
      this.log(`stream #${streamId}: sign request received, flags=${JSON.stringify(flags)}`);
      const pubKeyBuf = Buffer.isBuffer(pubKey)
        ? pubKey
        : pubKey && typeof pubKey === "object" && "getPublicSSH" in pubKey
          ? (pubKey as { getPublicSSH: () => Buffer }).getPublicSSH()
          : null;
      if (!pubKeyBuf) {
        this.log(`stream #${streamId}: sign failed — could not extract public key blob`);
        protocol.failureReply(req);
        return;
      }

      this.log(
        `stream #${streamId}: sign request key=${pubKeyBuf.subarray(0, 20).toString("hex")}… len=${data.length}`,
      );

      this.agent.sign(pubKeyBuf, data, flags, (err, signature) => {
        if (err || !signature) {
          this.log(`stream #${streamId}: sign failed: ${err?.message ?? "no signature"}`);
          protocol.failureReply(req);
          return;
        }
        this.log(`stream #${streamId}: sign success — ${signature.length} bytes`);
        protocol.signReply(req, signature);
      });
    });

    protocol.on("error", (err) => {
      this.log(`stream #${streamId}: protocol error: ${err.message}`);
    });

    const bridge = new AgentBridgeStream(protocol, logFn);
    cb(null, bridge);
  }

  destroy(): void {
    for (const p of this.protocols) {
      p.destroy();
    }
    this.protocols = [];
    this.agent.destroy();
  }
}
