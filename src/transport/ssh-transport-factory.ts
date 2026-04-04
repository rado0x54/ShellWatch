import type { EndpointInfo, EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import type { SshKeyInfo, SshKeyRepository } from "../db/repositories/key-repo.js";
import type { TerminalTransport } from "../terminal/transport.js";
import type { WebAuthnSshAgent } from "../webauthn/ssh-agent.js";
import type { PrivateKeyProvider } from "./key-directory-watcher.js";
import { connectSsh, connectSshWithAgent } from "./ssh-transport.js";

export interface WebAuthnAgentResult {
  agent: WebAuthnSshAgent;
  /** Called when the transport closes — should unregister the agent and clean up */
  cleanup: () => void;
}

export interface WebAuthnAgentFactory {
  /** Create a WebAuthn agent for the given credential — returns null if no browser is available */
  (credential: WebAuthnCredentialInfo, rpId: string): WebAuthnAgentResult | null;
}

/** Look up a WebAuthn credential by ID */
export type CredentialLookup = (id: string) => WebAuthnCredentialInfo | null;

export interface SshTransportFactoryOptions {
  createWebAuthnAgent?: WebAuthnAgentFactory;
  findCredential?: CredentialLookup;
}

/**
 * Creates SSH transport connections for terminal sessions.
 *
 * Resolves endpoint config + key material and connects via ssh2,
 * using either file-based keys or a WebAuthn browser-signing agent.
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

    // Passkey-based endpoint — use WebAuthn browser signing
    if (endpoint.passkeyId) {
      return this.connectWithWebAuthn(endpoint);
    }

    // File-based key
    if (endpoint.keyId) {
      const keyInfo = await this.keyRepo.findById(endpoint.keyId);
      if (!keyInfo) {
        throw new Error(`SSH key "${endpoint.keyId}" not found`);
      }
      return this.connectWithFileKey(endpoint, keyInfo);
    }

    throw new Error(`No SSH key configured for endpoint ${endpointId}`);
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
}
