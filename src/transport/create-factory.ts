import { randomUUID } from "node:crypto";
import type { ShellWatchDB } from "../db/connection.js";
import type { AccountRepository, SshKeyRepository } from "../db/index.js";
import { findCredentialsForAccount } from "../db/repositories/credential-queries.js";
import type { AgentForwardingContext, EndpointAuthContext } from "../pending-action/index.js";
import {
  buildFileKeyEntry,
  buildPasskeyEntry,
  CompositeSshAgent,
  SigningBridge,
  type FileKeySignRequest,
  type SignRequest,
} from "../webauthn/index.js";
import { ForwardingAgent } from "./forwarding-agent.js";
import type { KeyDirectoryWatcher } from "./key-directory-watcher.js";
import { SshTransportFactory } from "./ssh-transport-factory.js";

export interface CreateFactoryParams {
  db: ShellWatchDB;
  keyRepo: SshKeyRepository;
  accountRepo: AccountRepository;
  keyWatcher: KeyDirectoryWatcher;
  signingBridge: SigningBridge;
  rpId: string;
  agentLog: { current?: { error(msg: string): void } };
  /**
   * Cancel all pending sign prompts tied to a given SSH connection when its
   * client closes or errors. Prevents stranded popups that would otherwise
   * try to resolve signing against a dead ssh2 client. See #91.
   */
  onConnectionEnded?: (connectionId: string, reason: string) => void;
}

export function createSshTransportFactoryFromConfig(
  params: CreateFactoryParams,
): SshTransportFactory {
  const { db, keyRepo, accountRepo, keyWatcher, signingBridge, rpId, agentLog, onConnectionEnded } =
    params;

  return new SshTransportFactory(keyRepo, keyWatcher, {
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
      sessionId,
      trigger,
    }) => {
      const passkeyEntries = passkeys.map((c) => buildPasskeyEntry(c)).filter((e) => e !== null);

      const address = `${endpoint.username}@${endpoint.host}:${endpoint.port}`;

      const endpointAuthContext = (): EndpointAuthContext => ({
        source: "endpoint-auth",
        endpointLabel: endpoint.label,
        endpointAddress: address,
        trigger,
      });

      const forwardingContext = (): AgentForwardingContext => ({
        source: "agent-forwarding",
        endpointLabel: endpoint.label,
        endpointAddress: address,
        sessionId,
      });

      const redirectTo = `/session/${sessionId}`;

      const onSignRequest = (request: SignRequest) => {
        signingBridge.handleSignRequest(
          request,
          endpoint.accountId,
          endpointAuthContext(),
          redirectTo,
        );
      };

      const onFileKeySignRequest = (request: FileKeySignRequest) => {
        signingBridge.handleKeyApproveRequest(
          request,
          endpoint.accountId,
          endpointAuthContext(),
          redirectTo,
        );
      };

      const forwardingOnSignRequest = (request: SignRequest) => {
        signingBridge.handleSignRequest(
          request,
          endpoint.accountId,
          forwardingContext(),
          redirectTo,
        );
      };

      const forwardingOnFileKeySignRequest = (request: FileKeySignRequest) => {
        signingBridge.handleKeyApproveRequest(
          request,
          endpoint.accountId,
          forwardingContext(),
          redirectTo,
        );
      };

      const fileKeyEntries = isAdmin
        ? fileKeys
            .map((fk) => buildFileKeyEntry(fk.privateKey, fk.label, fk.fingerprint))
            .filter((e) => e !== null)
        : [];

      if (fileKeyEntries.length === 0 && passkeyEntries.length === 0) return null;

      const connectionId = randomUUID();

      const baseParams = {
        passkeys: passkeyEntries,
        fileKeys: fileKeyEntries,
        rpId,
        endpointLabel: endpoint.label,
        endpointAddress: address,
        userVerification: endpoint.userVerification,
        connectionId,
        onSignRequest,
        onFileKeySignRequest,
        logger: agentLog.current,
      };

      const agent = agentForward
        ? new ForwardingAgent({
            ...baseParams,
            forwardingOnSignRequest,
            forwardingOnFileKeySignRequest,
          })
        : new CompositeSshAgent(baseParams);

      // Guards against double-invocation: the factory calls cleanup() in the
      // connect-failure catch, and the transport's "close" listener also
      // calls it on normal teardown. Idempotence means we don't double-cancel
      // actions or fire onConnectionEnded twice.
      let cleanedUp = false;
      return {
        agent,
        cleanup: () => {
          if (cleanedUp) return;
          cleanedUp = true;
          agent.destroy();
          onConnectionEnded?.(connectionId, "SSH connection closed");
        },
      };
    },
  });
}
