import type { EndpointInfo, EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import type { SshKeyInfo, SshKeyRepository } from "../db/repositories/key-repo.js";
import type { TerminalTransport } from "../terminal/transport.js";
import type { WebAuthnSshAgent } from "../webauthn/ssh-agent.js";
import type { PrivateKeyProvider } from "./key-directory-watcher.js";
import { connectSsh, connectSshWithAgent, type AgentForwardOptions } from "./ssh-transport.js";

export interface AgentResult {
  agent: WebAuthnSshAgent;
  /** Called when the transport closes — should unregister the agent and clean up */
  cleanup: () => void;
}

export interface WebAuthnAgentFactory {
  /** Create a WebAuthn agent for a single assigned passkey — returns null if no browser is available */
  (credential: WebAuthnCredentialInfo, rpId: string): AgentResult | null;
}

export interface AutoNegotiateAgentFactory {
  /**
   * Create an agent for auto-negotiation — returns null if no browser is available.
   * For admin: returns CompositeSshAgent (file keys + passkeys).
   * For non-admin: returns WebAuthnSshAgent (passkeys only).
   */
  (params: {
    endpoint: EndpointInfo;
    fileKeys: Array<{ publicKey: string; privateKey: string }>;
    passkeys: WebAuthnCredentialInfo[];
    isAdmin: boolean;
    rpId: string;
  }): AgentResult | null;
}

/** Look up a WebAuthn credential by ID */
export type CredentialLookup = (id: string) => WebAuthnCredentialInfo | null;

/** Find all non-revoked WebAuthn credentials for an account */
export type CredentialsForAccountLookup = (accountId: string) => WebAuthnCredentialInfo[];

/** Check if an account is the admin account */
export type AdminCheck = (accountId: string) => boolean;

export interface ForwardingAgentResult {
  agent: WebAuthnSshAgent;
  cleanup: () => void;
}

export interface SshTransportFactoryOptions {
  rpId: string;
  createWebAuthnAgent?: WebAuthnAgentFactory;
  createAutoNegotiateAgent?: AutoNegotiateAgentFactory;
  findCredential?: CredentialLookup;
  findCredentialsForAccount?: CredentialsForAccountLookup;
  isAdmin?: AdminCheck;
  /** Look up whether agent forwarding is enabled for a given account */
  getAgentForward?: (accountId: string) => Promise<boolean>;
  /** Build an agent containing all available keys for forwarding to the remote host */
  createForwardingAgent?: (accountId: string) => ForwardingAgentResult | null;
}

/**
 * Creates SSH transport connections for terminal sessions.
 *
 * Resolves endpoint config + key material and connects via ssh2,
 * using either file-based keys, a WebAuthn browser-signing agent,
 * or an auto-negotiation agent that tries all available keys.
 */
export class SshTransportFactory {
  constructor(
    private endpointRepo: EndpointRepository,
    private keyRepo: SshKeyRepository,
    private keyProvider: PrivateKeyProvider,
    private options: SshTransportFactoryOptions,
  ) {}

  async create(endpointId: string): Promise<TerminalTransport> {
    const endpoint = await this.endpointRepo.findById(endpointId);
    if (!endpoint) {
      throw new Error(`Unknown endpoint: ${endpointId}`);
    }

    const agentForward = (await this.options.getAgentForward?.(endpoint.accountId)) ?? false;

    // Mode 1: Passkey-based endpoint — use WebAuthn browser signing (direct, no modal)
    if (endpoint.passkeyId) {
      return this.connectWithWebAuthn(endpoint, agentForward);
    }

    // Mode 2: File-based key
    if (endpoint.keyId) {
      const keyInfo = await this.keyRepo.findById(endpoint.keyId);
      if (!keyInfo) {
        throw new Error(`SSH key "${endpoint.keyId}" not found`);
      }
      return this.connectWithFileKey(endpoint, keyInfo, agentForward);
    }

    // Mode 3: No key assigned — auto-negotiate with all available keys
    return this.connectWithAutoNegotiate(endpoint, agentForward);
  }

  private async connectWithWebAuthn(
    endpoint: EndpointInfo,
    agentForward: boolean,
  ): Promise<TerminalTransport> {
    if (!this.options.findCredential) {
      throw new Error("WebAuthn key configured but no credential lookup provided");
    }
    if (!this.options.createWebAuthnAgent) {
      throw new Error("WebAuthn key configured but no agent factory provided");
    }

    const credential = this.options.findCredential(endpoint.passkeyId!);
    if (!credential) {
      throw new Error(`WebAuthn credential "${endpoint.passkeyId}" not found`);
    }
    if (credential.revoked) {
      throw new Error(`WebAuthn credential "${endpoint.passkeyId}" has been revoked`);
    }

    const result = this.options.createWebAuthnAgent(credential, this.options.rpId);
    if (!result) {
      throw new Error(
        "WebAuthn authentication requires a browser session. Open ShellWatch in a browser.",
      );
    }
    const transport = await connectSshWithAgent(endpoint, result.agent, { agentForward });
    transport.on("close", () => result.cleanup());
    return transport;
  }

  private async connectWithFileKey(
    endpoint: EndpointInfo,
    keyInfo: SshKeyInfo,
    agentForward: boolean,
  ): Promise<TerminalTransport> {
    const privateKey = this.keyProvider.getPrivateKey(keyInfo.fingerprint);
    if (!privateKey) {
      throw new Error(
        `SSH key "${endpoint.keyId}" is unavailable (fingerprint: ${keyInfo.fingerprint}). ` +
          "Ensure the corresponding .pem file is in the key directory.",
      );
    }

    const fwdOpts: AgentForwardOptions = {};
    let fwdCleanup: (() => void) | undefined;
    if (agentForward) {
      const fwdResult = this.options.createForwardingAgent?.(endpoint.accountId);
      if (fwdResult) {
        fwdOpts.agentForward = true;
        fwdOpts.forwardingAgent = fwdResult.agent;
        fwdCleanup = fwdResult.cleanup;
      }
    }

    const transport = await connectSsh(endpoint, privateKey, fwdOpts);
    if (fwdCleanup) transport.on("close", fwdCleanup);
    return transport;
  }

  private async connectWithAutoNegotiate(
    endpoint: EndpointInfo,
    agentForward: boolean,
  ): Promise<TerminalTransport> {
    if (!this.options.createAutoNegotiateAgent) {
      throw new Error(
        "No SSH key configured for endpoint and no auto-negotiate agent factory provided",
      );
    }

    const isAdmin = this.options.isAdmin?.(endpoint.accountId) ?? false;

    // Gather file keys (admin only)
    const fileKeys: Array<{ publicKey: string; privateKey: string }> = [];
    if (isAdmin) {
      const allKeys = await this.keyRepo.findAll();
      for (const key of allKeys) {
        if (key.type !== "file" || !key.enabled) continue;
        const privateKey = this.keyProvider.getPrivateKey(key.fingerprint);
        if (privateKey) {
          fileKeys.push({ publicKey: key.publicKey, privateKey });
        }
      }
    }

    // Gather passkeys for this account
    const passkeys = this.options.findCredentialsForAccount?.(endpoint.accountId) ?? [];

    if (fileKeys.length === 0 && passkeys.length === 0) {
      throw new Error(
        "No SSH keys available for auto-negotiation. " +
          "Register a passkey or add a file-based key to the key directory.",
      );
    }

    const result = this.options.createAutoNegotiateAgent({
      endpoint,
      fileKeys,
      passkeys,
      isAdmin,
      rpId: this.options.rpId,
    });

    if (!result) {
      if (fileKeys.length > 0) {
        throw new Error(
          "WebAuthn authentication requires a browser session. " +
            "Open ShellWatch in a browser, or assign a file-based key to this endpoint.",
        );
      }
      throw new Error(
        "WebAuthn authentication requires a browser session. Open ShellWatch in a browser.",
      );
    }

    const transport = await connectSshWithAgent(endpoint, result.agent, { agentForward });
    transport.on("close", () => result.cleanup());
    return transport;
  }
}
