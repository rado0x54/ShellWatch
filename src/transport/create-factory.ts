import type { ShellWatchDB } from "../db/connection.js";
import type { AccountRepository, EndpointRepository, SshKeyRepository } from "../db/index.js";
import {
  findCredentialById,
  findCredentialsForAccount,
} from "../db/repositories/credential-queries.js";
import {
  buildFileKeyEntry,
  buildPasskeyEntry,
  CompositeSshAgent,
  SigningBridge,
  WebAuthnSshAgent,
  type SignRequest,
} from "../webauthn/index.js";
import { ForwardingAgent } from "./forwarding-agent.js";
import type { KeyDirectoryWatcher } from "./key-directory-watcher.js";
import { SshTransportFactory } from "./ssh-transport-factory.js";

export interface CreateFactoryParams {
  db: ShellWatchDB;
  endpointRepo: EndpointRepository;
  keyRepo: SshKeyRepository;
  accountRepo: AccountRepository;
  keyWatcher: KeyDirectoryWatcher;
  signingBridge: SigningBridge;
  rpId: string;
  agentLog: { current?: { error(msg: string): void } };
}

export function createSshTransportFactoryFromConfig(
  params: CreateFactoryParams,
): SshTransportFactory {
  const { db, endpointRepo, keyRepo, accountRepo, keyWatcher, signingBridge, rpId, agentLog } =
    params;

  /** Register an agent with the signing bridge and return a cleanup function */
  function registerAgent(prefix: string, agent: WebAuthnSshAgent) {
    const agentId = `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    signingBridge.registerAgent(agentId, agent);
    return {
      agent,
      cleanup: () => {
        signingBridge.unregisterAgent(agentId);
        agent.destroy();
      },
    };
  }

  return new SshTransportFactory(endpointRepo, keyRepo, keyWatcher, {
    rpId,
    findCredential: (id) => findCredentialById(db, id),
    findCredentialsForAccount: (accountId) => findCredentialsForAccount(db, accountId),
    isAdmin: (accountId) => accountRepo.isAdmin(accountId),

    getAgentForward: async (accountId) => {
      const account = await accountRepo.findById(accountId);
      return account?.agentForward ?? false;
    },

    createForwardingAgent: (accountId) => {
      const isAdmin = accountRepo.isAdmin(accountId);

      // Gather file keys (admin gets all, non-admin gets none for now)
      const fileKeyEntries = isAdmin
        ? keyWatcher
            .getAvailableKeys()
            .map((k) => buildFileKeyEntry(k.privateKeyContent))
            .filter((e) => e !== null)
        : [];

      // Gather passkeys if browser is connected
      const passkeys = findCredentialsForAccount(db, accountId);
      const passkeyEntries = signingBridge.hasClients
        ? passkeys.map((c) => buildPasskeyEntry(c)).filter((e) => e !== null)
        : [];

      if (fileKeyEntries.length === 0 && passkeyEntries.length === 0) return null;

      const onSignRequest =
        passkeyEntries.length > 0 && signingBridge
          ? (request: SignRequest) => signingBridge.handleSignRequest(request)
          : () => {};

      const baseAgent = new CompositeSshAgent({
        passkeys: passkeyEntries,
        fileKeys: fileKeyEntries,
        rpId,
        onSignRequest,
        logger: agentLog.current,
      });

      const agentId = `fwd_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      signingBridge.registerAgent(agentId, baseAgent);

      const fwdAgent = new ForwardingAgent(baseAgent);
      return {
        agent: fwdAgent,
        cleanup: () => {
          signingBridge.unregisterAgent(agentId);
          fwdAgent.destroy();
        },
      };
    },

    // Single assigned passkey — direct WebAuthn sign, no modal
    createWebAuthnAgent: (credential, rpId) => {
      if (!signingBridge.hasClients) return null;
      const agent = new WebAuthnSshAgent({
        passkeys: [buildPasskeyEntry(credential)!],
        rpId,
        onSignRequest: (request: SignRequest) => signingBridge.handleSignRequest(request),
        logger: agentLog.current,
      });
      return registerAgent("agent", agent);
    },

    // Auto-negotiate — admin gets CompositeSshAgent, non-admin gets WebAuthnSshAgent
    createAutoNegotiateAgent: ({ endpoint, fileKeys, passkeys, isAdmin, rpId }) => {
      // Need a browser if there are passkeys to try
      if (passkeys.length > 0 && !signingBridge.hasClients) {
        if (fileKeys.length === 0) return null;
      }

      const passkeyEntries = signingBridge.hasClients
        ? passkeys.map((c) => buildPasskeyEntry(c)).filter((e) => e !== null)
        : [];

      const address = `${endpoint.username}@${endpoint.host}:${endpoint.port}`;
      const baseParams = {
        passkeys: passkeyEntries,
        rpId,
        endpointLabel: endpoint.label,
        endpointAddress: address,
        onSignRequest: (request: SignRequest) => signingBridge.handleSignRequest(request),
        logger: agentLog.current,
      };

      if (isAdmin) {
        // Admin: CompositeSshAgent with file keys + passkeys
        const fileKeyEntries = fileKeys
          .map((fk) => buildFileKeyEntry(fk.privateKey))
          .filter((e) => e !== null);

        if (fileKeyEntries.length === 0 && passkeyEntries.length === 0) return null;

        const agent = new CompositeSshAgent({ ...baseParams, fileKeys: fileKeyEntries });
        return registerAgent("composite", agent);
      }

      // Non-admin: WebAuthnSshAgent with passkeys only
      if (passkeyEntries.length === 0) return null;
      const agent = new WebAuthnSshAgent(baseParams);
      return registerAgent("agent", agent);
    },
  });
}
