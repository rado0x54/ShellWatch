import type { ShellWatchDB } from "../db/connection.js";
import type { AccountRepository, EndpointRepository, SshKeyRepository } from "../db/index.js";
import { findCredentialsForAccount } from "../db/repositories/credential-queries.js";
import {
  buildFileKeyEntry,
  buildPasskeyEntry,
  CompositeSshAgent,
  SigningBridge,
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

  return new SshTransportFactory(endpointRepo, keyRepo, keyWatcher, {
    rpId,
    findCredentialsForAccount: (accountId) => findCredentialsForAccount(db, accountId),
    isAdmin: (accountId) => accountRepo.isAdmin(accountId),

    getAgentForward: async (accountId) => {
      const account = await accountRepo.findById(accountId);
      return account?.agentForward ?? false;
    },

    createAgent: ({ endpoint, fileKeys, passkeys, isAdmin, rpId, agentForward }) => {
      // Need a browser if there are passkeys to try
      if (passkeys.length > 0 && !signingBridge.hasClients) {
        if (fileKeys.length === 0) return null;
      }

      const passkeyEntries = signingBridge.hasClients
        ? passkeys.map((c) => buildPasskeyEntry(c)).filter((e) => e !== null)
        : [];

      const address = `${endpoint.username}@${endpoint.host}:${endpoint.port}`;
      const onSignRequest = (request: SignRequest) => signingBridge.handleSignRequest(request);

      const fileKeyEntries = isAdmin
        ? fileKeys.map((fk) => buildFileKeyEntry(fk.privateKey)).filter((e) => e !== null)
        : [];

      if (fileKeyEntries.length === 0 && passkeyEntries.length === 0) return null;

      const baseParams = {
        passkeys: passkeyEntries,
        fileKeys: fileKeyEntries,
        rpId,
        endpointLabel: endpoint.label,
        endpointAddress: address,
        onSignRequest,
        logger: agentLog.current,
      };

      // ForwardingAgent when forwarding is enabled, CompositeSshAgent otherwise
      const agent = agentForward
        ? new ForwardingAgent(baseParams)
        : new CompositeSshAgent(baseParams);

      const agentId = `agent_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      signingBridge.registerAgent(agentId, agent);

      return {
        agent,
        cleanup: () => {
          signingBridge.unregisterAgent(agentId);
          agent.destroy();
        },
      };
    },
  });
}
