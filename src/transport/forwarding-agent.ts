/**
 * SSH agent that supports both authentication and agent forwarding.
 *
 * Extends CompositeSshAgent (file keys + passkeys) and adds `getStream()`
 * which ssh2 requires for piping `auth-agent@openssh.com` forwarding
 * channels (see client.js ~line 1998).
 *
 * Inheritance: ForwardingAgent → CompositeSshAgent → WebAuthnSshAgent → BaseAgent
 */

import ssh2 from "ssh2";
import type { ParsedKey } from "ssh2";
import {
  CompositeSshAgent,
  type CompositeAgentParams,
  type FileKeySignRequest,
} from "../webauthn/composite-ssh-agent.js";
import { toPublicKeyBlob, type SignRequest } from "../webauthn/ssh-agent.js";

export interface ForwardingAgentParams extends CompositeAgentParams {
  /** Callback for passkey signing triggered by the auth-agent@openssh.com channel. */
  forwardingOnSignRequest: (request: SignRequest) => void;
  /** Callback for file-key approval triggered by the auth-agent@openssh.com channel. */
  forwardingOnFileKeySignRequest: (request: FileKeySignRequest) => void;
}

const { utils } = ssh2;

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
  on(event: string, listener: (...args: never[]) => void): this;
  destroy(): void;
}

export class ForwardingAgent extends CompositeSshAgent {
  private protocols: AgentProtocolInstance[] = [];
  private forwardingOnSignRequest: (request: SignRequest) => void;
  private forwardingOnFileKeySignRequest: (request: FileKeySignRequest) => void;

  constructor(params: ForwardingAgentParams) {
    super(params);
    this.forwardingOnSignRequest = params.forwardingOnSignRequest;
    this.forwardingOnFileKeySignRequest = params.forwardingOnFileKeySignRequest;
  }

  /**
   * Called by ssh2 for each incoming `auth-agent@openssh.com` channel.
   * Creates a server-mode AgentProtocol stream that handles identity
   * and sign requests by delegating to this agent's getIdentities + a
   * sign path that routes through the forwarding-specific callbacks
   * (so `/sign/:id` sees source="agent-forwarding" for these requests).
   */
  getStream(cb: (err: Error | null, stream?: NodeJS.ReadWriteStream) => void): void {
    const protocol = new AgentProtocol(false); // server mode
    this.protocols.push(protocol);

    protocol.on("identities", (req) => {
      this.getIdentities((err, keys) => {
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
      const pubKeyBuf = toPublicKeyBlob(pubKey as Buffer);
      if (!pubKeyBuf) {
        protocol.failureReply(req);
        return;
      }
      this.signWithCallbacks(
        pubKeyBuf,
        data,
        flags,
        (err, signature) => {
          if (err || !signature) {
            protocol.failureReply(req);
            return;
          }
          protocol.signReply(req, signature);
        },
        {
          onSignRequest: this.forwardingOnSignRequest,
          onFileKeySignRequest: this.forwardingOnFileKeySignRequest,
        },
      );
    });

    cb(null, protocol);
  }

  override destroy(): void {
    for (const p of this.protocols) {
      p.destroy();
    }
    this.protocols = [];
    super.destroy();
  }
}
