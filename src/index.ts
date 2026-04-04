import { loadConfig } from "./config/index.js";
import { startCleanupJob } from "./db/cleanup.js";
import {
  createDatabase,
  DrizzleAccountRepository,
  DrizzleApiKeyRepository,
  DrizzleEndpointRepository,
  DrizzleSshKeyRepository,
  runMigrations,
  seedFromConfig,
} from "./db/index.js";
import {
  findCredentialById,
  findCredentialsForAccount,
} from "./db/repositories/credential-queries.js";
import { buildApp } from "./server/app.js";
import { TerminalManager } from "./terminal/index.js";
import { KeyDirectoryWatcher, SshTransportFactory } from "./transport/index.js";
import {
  buildFileKeyEntry,
  buildPasskeyEntry,
  CompositeSshAgent,
  SigningBridge,
  WebAuthnSshAgent,
} from "./webauthn/index.js";

const HOST = process.env.HOST ?? "0.0.0.0";

try {
  const config = loadConfig();
  const PORT = config.server.port;

  // Initialize database
  const { db, close: closeDb } = createDatabase();
  runMigrations(db);
  const seedResult = seedFromConfig(db, config);

  const endpointRepo = new DrizzleEndpointRepository(db);
  const keyRepo = new DrizzleSshKeyRepository(db);
  const apiKeyRepo = new DrizzleApiKeyRepository(db);
  const accountRepo = new DrizzleAccountRepository(db);

  // Scan key directory, auto-register keys in DB, and watch for changes
  const keyWatcher = new KeyDirectoryWatcher(config.keyDirectory, keyRepo);
  const scannedKeys = await keyWatcher.start();

  // WebAuthn signing bridge — connects SSH agent to browser
  const signingBridge = new SigningBridge();

  // Late-binding logger — set after buildApp(), but only used at session time
  const agentLog: { current?: { error(msg: string): void } } = {};

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

  const sshTransportFactory = new SshTransportFactory(endpointRepo, keyRepo, keyWatcher, {
    findCredential: (id) => findCredentialById(db, id),
    findCredentialsForAccount: (accountId) => findCredentialsForAccount(db, accountId),
    isAdmin: (accountId) => accountRepo.isAdmin(accountId),

    // Single assigned passkey — direct WebAuthn sign, no modal
    createWebAuthnAgent: (credential, rpId) => {
      if (!signingBridge.hasClients) return null;
      const agent = new WebAuthnSshAgent({
        passkeys: [buildPasskeyEntry(credential)!],
        rpId,
        onSignRequest: (request) => signingBridge.handleSignRequest(request),
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
        onSignRequest: (request: import("./webauthn/ssh-agent.js").SignRequest) =>
          signingBridge.handleSignRequest(request),
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

  const terminalManager = new TerminalManager(endpointRepo, (id) => sshTransportFactory.create(id));

  const app = await buildApp({
    config,
    terminalManager,
    endpointRepo,
    keyRepo,
    accountRepo,
    db,
    wsExtensions: [signingBridge],
    keyAvailability: keyWatcher,
    apiKeyRepo,
  });

  agentLog.current = { error: (msg) => app.log.error(msg) };

  app.log.info(`Found ${scannedKeys.length} SSH key(s) in ${config.keyDirectory}`);
  for (const key of scannedKeys) {
    app.log.info(`  ${key.filename}: ${key.type} (${key.fingerprint})`);
  }
  if (seedResult.seededApiKey) {
    app.log.info(`Seeded API key (prefix: ${seedResult.apiKeyPrefix}…)`);
  }
  if (seedResult.seededAdminAccount) {
    app.log.info(`Seeded admin account (${seedResult.seededAdminId})`);
  }
  if (seedResult.seededAdminPasskey) {
    app.log.info(`Seeded admin passkey (${config.seedAdminPasskey?.label ?? "Admin Passkey"})`);
  }

  const endpoints = await endpointRepo.findAll();
  app.log.info(`${endpoints.length} endpoint(s) in database`);

  // Inactivity cleanup: delete accounts unused for 90+ days (admin exempt)
  const stopCleanup = startCleanupJob(db, 90, (deletedIds) => {
    app.log.info(`Cleaned up ${deletedIds.length} inactive account(s)`);
  });

  const shutdown = async () => {
    stopCleanup();
    keyWatcher.stop();
    terminalManager.destroy();
    accountRepo.destroy();
    await app.close();
    closeDb();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  await app.listen({ port: PORT, host: HOST });
  const base = config.server.basePath || "";
  app.log.info(`ShellWatch server listening on http://${HOST}:${PORT}${base}`);
  app.log.info(`MCP endpoint available at http://${HOST}:${PORT}${base}/mcp`);
} catch (err) {
  // Fatal startup error — app may not exist yet, use stderr directly
  process.stderr.write(`Failed to start ShellWatch: ${(err as Error).message}\n`);
  process.exit(1);
}
