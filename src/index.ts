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
import { findCredentialsForAccount } from "./db/repositories/credential-queries.js";
import { buildApp } from "./server/app.js";
import { TerminalManager } from "./terminal/index.js";
import { KeyDirectoryWatcher } from "./transport/index.js";
import { createSshTransportFactoryFromConfig } from "./transport/create-factory.js";
import { SigningBridge } from "./webauthn/index.js";

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

  const sshTransportFactory = createSshTransportFactoryFromConfig({
    db,
    endpointRepo,
    keyRepo,
    accountRepo,
    keyWatcher,
    signingBridge,
    rpId: config.security.rpId,
    agentLog,
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
    ...(config.agentSocket.proxyEnabled && {
      agentProxy: {
        keyProvider: keyWatcher,
        signingBridge,
        findCredentialsForAccount: (accountId: string) => findCredentialsForAccount(db, accountId),
        rpId: config.security.rpId,
      },
    }),
  });

  agentLog.current = { error: (msg) => app.log.error(msg) };

  app.log.info(`WebAuthn rpId: ${config.security.rpId}`);
  app.log.info(`Trusted origins: ${config.security.trustedWebauthnOrigins.join(", ")}`);
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
    const labels = config.seedAdminPasskeys.map((pk) => pk.label).join(", ");
    app.log.info(`Seeded admin passkey(s): ${labels}`);
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
  app.log.info(`ShellWatch server listening on http://${HOST}:${PORT}`);
  app.log.info(`MCP endpoint available at http://${HOST}:${PORT}/mcp`);
} catch (err) {
  // Fatal startup error — app may not exist yet, use stderr directly
  process.stderr.write(`Failed to start ShellWatch: ${(err as Error).message}\n`);
  process.exit(1);
}
