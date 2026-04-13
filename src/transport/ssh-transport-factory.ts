import type { EndpointInfo, EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import type { SshKeyRepository } from "../db/repositories/key-repo.js";
import type { EndpointAuthTrigger } from "../pending-action/types.js";
import type { TerminalTransport, TransportFactoryParams } from "../terminal/transport.js";
import type { WebAuthnSshAgent } from "../webauthn/ssh-agent.js";
import type { PrivateKeyProvider } from "./key-directory-watcher.js";
import { connectSshWithAgent } from "./ssh-transport.js";

export interface AgentResult {
  agent: WebAuthnSshAgent;
  /** Called when the transport closes — should unregister the agent and clean up */
  cleanup: () => void;
}

export interface AgentFactory {
  /**
   * Create an agent for the given endpoint.
   * When agentForward is true, returns a ForwardingAgent (with getStream()).
   * Returns null if no keys are available.
   */
  (params: {
    endpoint: EndpointInfo;
    fileKeys: Array<{ publicKey: string; privateKey: string; label: string; fingerprint: string }>;
    passkeys: WebAuthnCredentialInfo[];
    isAdmin: boolean;
    rpId: string;
    agentForward: boolean;
    sessionId: string;
    trigger: EndpointAuthTrigger;
  }): AgentResult | null;
}

/** Find all non-revoked WebAuthn credentials for an account */
export type CredentialsForAccountLookup = (accountId: string) => WebAuthnCredentialInfo[];

/** Check if an account is the admin account */
export type AdminCheck = (accountId: string) => boolean;

export interface SshTransportFactoryOptions {
  rpId: string;
  createAgent: AgentFactory;
  findCredentialsForAccount?: CredentialsForAccountLookup;
  isAdmin?: AdminCheck;
  /** Look up whether agent forwarding is enabled for a given account */
  getAgentForward?: (accountId: string) => Promise<boolean>;
}

/**
 * Creates SSH transport connections for terminal sessions.
 *
 * Always auto-negotiates keys — builds an agent with all available
 * file keys and passkeys, then connects via ssh2.
 */
export class SshTransportFactory {
  constructor(
    private endpointRepo: EndpointRepository,
    private keyRepo: SshKeyRepository,
    private keyProvider: PrivateKeyProvider,
    private options: SshTransportFactoryOptions,
  ) {}

  async create(params: TransportFactoryParams): Promise<TerminalTransport> {
    const { endpointId, sessionId, trigger } = params;
    const endpoint = await this.endpointRepo.findById(endpointId);
    if (!endpoint) {
      throw new Error(`Unknown endpoint: ${endpointId}`);
    }

    const agentForward = (await this.options.getAgentForward?.(endpoint.accountId)) ?? false;
    const isAdmin = this.options.isAdmin?.(endpoint.accountId) ?? false;

    // Gather file keys (admin only)
    const fileKeys: Array<{
      publicKey: string;
      privateKey: string;
      label: string;
      fingerprint: string;
    }> = [];
    if (isAdmin) {
      const allKeys = await this.keyRepo.findAll();
      for (const key of allKeys) {
        if (key.type !== "file" || !key.enabled) continue;
        const privateKey = this.keyProvider.getPrivateKey(key.fingerprint);
        if (privateKey) {
          fileKeys.push({
            publicKey: key.publicKey,
            privateKey,
            label: key.label,
            fingerprint: key.fingerprint,
          });
        }
      }
    }

    // Gather passkeys for this account
    const passkeys = this.options.findCredentialsForAccount?.(endpoint.accountId) ?? [];

    if (fileKeys.length === 0 && passkeys.length === 0) {
      throw new Error(
        "No SSH keys available. " +
          "Register a passkey or add a file-based key to the key directory.",
      );
    }

    const result = this.options.createAgent({
      endpoint,
      fileKeys,
      passkeys,
      isAdmin,
      rpId: this.options.rpId,
      agentForward,
      sessionId,
      trigger,
    });

    if (!result) {
      throw new Error("No SSH keys available for this endpoint.");
    }

    let transport: TerminalTransport;
    try {
      transport = await connectSshWithAgent(endpoint, result.agent, { agentForward });
    } catch (err) {
      // Also run cleanup on connection failure so pending sign prompts tied to
      // this (doomed) connection don't linger on screen after the SSH client
      // has been torn down. See #91.
      result.cleanup();
      throw err;
    }
    transport.on("close", () => result.cleanup());
    return transport;
  }
}
