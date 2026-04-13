import { loadConfig } from "./config/index.js";
import { startCleanupJob } from "./db/cleanup.js";
import {
  createDatabase,
  DrizzleAccountRepository,
  DrizzleApiKeyRepository,
  DrizzleEndpointRepository,
  DrizzlePushSubscriptionRepository,
  DrizzleSshKeyRepository,
  runMigrations,
  seedFromConfig,
} from "./db/index.js";
import { findCredentialsForAccount } from "./db/repositories/credential-queries.js";
import {
  NotificationDispatcher,
  PendingActionStore,
  PushChannel,
  WebSocketChannel,
} from "./pending-action/index.js";
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

  // PendingAction system — manages sign request lifecycle + notifications
  const actionStore = new PendingActionStore();
  const baseUrl = config.server.externalUrl;
  const dispatcher = new NotificationDispatcher(baseUrl);
  const wsChannel = new WebSocketChannel();
  dispatcher.register(wsChannel);

  // Web Push notification channel (optional — requires VAPID config)
  let pushSubRepo: DrizzlePushSubscriptionRepository | undefined;
  if (config.vapid) {
    pushSubRepo = new DrizzlePushSubscriptionRepository(db);
    const pushChannel = new PushChannel({
      pushSubRepo,
      vapid: config.vapid,
    });
    dispatcher.register(pushChannel);
  }

  // SigningBridge — coordinates sign requests from agents → PendingAction → notifications
  const signingBridge = new SigningBridge({ actionStore, dispatcher });

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
    onConnectionEnded: (connectionId, reason) => {
      // When an SSH client dies, drop any sign prompts still tied to it so
      // they don't linger on screen and try to resolve against a dead ssh2
      // callback. The WS broadcast clears in-flight toasts on the client. #91
      const cancelled = actionStore.cancelForConnection(connectionId, reason);
      for (const action of cancelled) {
        wsChannel.broadcastResolved(action.id, action.accountId);
      }
    },
  });

  const terminalManager = new TerminalManager(endpointRepo, (params) =>
    sshTransportFactory.create(params),
  );

  const app = await buildApp({
    config,
    terminalManager,
    endpointRepo,
    keyRepo,
    accountRepo,
    db,
    wsExtensions: [wsChannel],
    keyAvailability: keyWatcher,
    apiKeyRepo,
    actionStore,
    wsChannel,
    pushSubRepo,
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

  if (config.vapid) {
    app.log.info("Web Push notifications enabled (VAPID configured)");
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
    actionStore.destroy();
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
