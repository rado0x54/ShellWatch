/**
 * Wraps a CompositeSshAgent with a `getStream()` method so ssh2's
 * agent forwarding channel handler can pipe raw agent protocol data
 * through it. Each call to `getStream()` creates a fresh AgentProtocol
 * stream backed by the same underlying agent.
 *
 * ssh2 requires `getStream(cb)` on the agent object to handle incoming
 * `auth-agent@openssh.com` channels (see client.js ~line 1998).
 */

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

/**
 * An agent wrapper that delegates identity/sign to a CompositeSshAgent
 * and provides `getStream()` for ssh2's agent forwarding channel handler.
 *
 * Extends BaseAgent so ssh2's `isAgent()` check passes (it uses instanceof).
 */
export class ForwardingAgent extends BaseAgent {
  private protocols: AgentProtocolInstance[] = [];
  private agent: WebAuthnSshAgent;

  constructor(agent: WebAuthnSshAgent) {
    super();
    this.agent = agent;
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
   * Creates a server-mode AgentProtocol stream that handles identity
   * and sign requests by delegating to the wrapped agent.
   */
  getStream(cb: (err: Error | null, stream?: NodeJS.ReadWriteStream) => void): void {
    const protocol = new AgentProtocol(false); // server mode
    this.protocols.push(protocol);

    protocol.on("identities", (req) => {
      this.agent.getIdentities((err, keys) => {
        if (err || !keys) {
          protocol.failureReply(req);
          return;
        }
        const parsed = keys
          .map((blob) => utils.parseKey(blob))
          .filter((k): k is ParsedKey => !!k && !(k instanceof Error));
        protocol.getIdentitiesReply(req, parsed);
      });
    });

    protocol.on("sign", (req, pubKey, data, flags) => {
      const pubKeyBuf = Buffer.isBuffer(pubKey)
        ? pubKey
        : pubKey && typeof pubKey === "object" && "getPublicSSH" in pubKey
          ? (pubKey as { getPublicSSH: () => Buffer }).getPublicSSH()
          : null;
      if (!pubKeyBuf) {
        protocol.failureReply(req);
        return;
      }

      this.agent.sign(pubKeyBuf, data, flags, (err, signature) => {
        if (err || !signature) {
          protocol.failureReply(req);
          return;
        }
        protocol.signReply(req, signature);
      });
    });

    cb(null, protocol);
  }

  destroy(): void {
    for (const p of this.protocols) {
      p.destroy();
    }
    this.protocols = [];
    this.agent.destroy();
  }
}
