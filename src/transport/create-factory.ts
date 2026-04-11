import type { ShellWatchDB } from "../db/connection.js";
import type { AccountRepository, EndpointRepository, SshKeyRepository } from "../db/index.js";
import { findCredentialsForAccount } from "../db/repositories/credential-queries.js";
import type { SignRequestContext } from "../pending-action/index.js";
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

    createAgent: ({
      endpoint,
      fileKeys,
      passkeys,
      isAdmin,
      rpId,
      agentForward,
      sessionId: _sessionId,
    }) => {
      const passkeyEntries = passkeys.map((c) => buildPasskeyEntry(c)).filter((e) => e !== null);

      const address = `${endpoint.username}@${endpoint.host}:${endpoint.port}`;

      const onSignRequest = (request: SignRequest) => {
        // Build context based on whether this is a forwarding agent session.
        // sessionId is not yet known at agent creation time (TerminalManager
        // generates it after the transport connects), so we omit it here.
        const context: SignRequestContext = agentForward
          ? {
              source: "forwarding-agent",
              endpointLabel: endpoint.label,
              endpointAddress: address,
              sessionId: "pending",
            }
          : {
              source: "ui",
              sourceIp: "127.0.0.1",
              endpointLabel: endpoint.label,
              endpointAddress: address,
              sessionId: "pending",
            };

        signingBridge.handleSignRequest(request, endpoint.accountId, context);
      };

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

      const agent = agentForward
        ? new ForwardingAgent(baseParams)
        : new CompositeSshAgent(baseParams);

      return {
        agent,
        cleanup: () => {
          agent.destroy();
        },
      };
    },
  });
}
