import type { EndpointInfo, EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import type { SshKeyInfo, SshKeyRepository } from "../db/repositories/key-repo.js";
import type { TerminalTransport } from "../terminal/transport.js";
import type { WebAuthnSshAgent } from "../webauthn/ssh-agent.js";
import type { PrivateKeyProvider } from "./key-directory-watcher.js";
import { connectSsh, connectSshWithAgent } from "./ssh-transport.js";

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

export interface SshTransportFactoryOptions {
  createWebAuthnAgent?: WebAuthnAgentFactory;
  createAutoNegotiateAgent?: AutoNegotiateAgentFactory;
  findCredential?: CredentialLookup;
  findCredentialsForAccount?: CredentialsForAccountLookup;
  isAdmin?: AdminCheck;
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
    private options: SshTransportFactoryOptions = {},
  ) {}

  async create(endpointId: string): Promise<TerminalTransport> {
    const endpoint = await this.endpointRepo.findById(endpointId);
    if (!endpoint) {
      throw new Error(`Unknown endpoint: ${endpointId}`);
    }

    // Mode 1: Passkey-based endpoint — use WebAuthn browser signing (direct, no modal)
    if (endpoint.passkeyId) {
      return this.connectWithWebAuthn(endpoint);
    }

    // Mode 2: File-based key
    if (endpoint.keyId) {
      const keyInfo = await this.keyRepo.findById(endpoint.keyId);
      if (!keyInfo) {
        throw new Error(`SSH key "${endpoint.keyId}" not found`);
      }
      return this.connectWithFileKey(endpoint, keyInfo);
    }

    // Mode 3: No key assigned — auto-negotiate with all available keys
    return this.connectWithAutoNegotiate(endpoint);
  }

  private async connectWithWebAuthn(endpoint: EndpointInfo): Promise<TerminalTransport> {
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

    // TODO: thread actual rpId from config instead of hardcoding "localhost"
    const result = this.options.createWebAuthnAgent(credential, "localhost");
    if (!result) {
      throw new Error(
        "WebAuthn authentication requires a browser session. Open ShellWatch in a browser.",
      );
    }
    const transport = await connectSshWithAgent(endpoint, result.agent);
    transport.on("close", () => result.cleanup());
    return transport;
  }

  private async connectWithFileKey(
    endpoint: EndpointInfo,
    keyInfo: SshKeyInfo,
  ): Promise<TerminalTransport> {
    const privateKey = this.keyProvider.getPrivateKey(keyInfo.fingerprint);
    if (!privateKey) {
      throw new Error(
        `SSH key "${endpoint.keyId}" is unavailable (fingerprint: ${keyInfo.fingerprint}). ` +
          "Ensure the corresponding .pem file is in the key directory.",
      );
    }
    return connectSsh(endpoint, privateKey);
  }

  private async connectWithAutoNegotiate(endpoint: EndpointInfo): Promise<TerminalTransport> {
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
      rpId: "localhost", // TODO: thread actual rpId from config
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

    const transport = await connectSshWithAgent(endpoint, result.agent);
    transport.on("close", () => result.cleanup());
    return transport;
  }
}
