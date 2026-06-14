// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import {
  DrizzleSessionLifecycleRepository,
  DrizzleSigningRequestsRepository,
  SessionLifecycleWriter,
  SigningRequestsWriter,
} from "./audit/index.js";
import { loadConfig } from "./config/index.js";
import { startCleanupJob } from "./db/cleanup.js";
import {
  createDatabase,
  DrizzleAccountRepository,
  DrizzleEndpointRepository,
  DrizzlePushSubscriptionRepository,
  DrizzleSshKeyRepository,
  runMigrations,
  seedFromConfig,
} from "./db/index.js";
import { findCredentialsForAccount } from "./db/repositories/credential-queries.js";
import { createHydraAdminClient, ensureSpaClient } from "./hydra/index.js";
import {
  NotificationDispatcher,
  PendingActionStore,
  PushChannel,
  WebSocketChannel,
} from "./pending-action/index.js";
import { AccountLifecycle } from "./server/account-lifecycle.js";
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
  const accountRepo = new DrizzleAccountRepository(db);
  const accountLifecycle = new AccountLifecycle();

  // Ory Hydra is the OAuth2/OIDC authority (#217). The admin client speaks the
  // admin API (:4445) for login/consent acceptance, client CRUD, introspection.
  const hydraAdmin = createHydraAdminClient({ adminUrl: config.hydra.adminUrl });
  // Provision the first-party public SPA client in Hydra (idempotent). Fail
  // fast — a missing/misconfigured Hydra means the web UI can't authenticate.
  try {
    await ensureSpaClient(hydraAdmin, config.hydra);
  } catch (err) {
    throw new Error(
      `Failed to provision the SPA client in Hydra at ${config.hydra.adminUrl}. ` +
        `Is Hydra running? (docker compose up -d hydra). ` +
        `Cause: ${(err as Error).message}`,
      { cause: err },
    );
  }

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
      if (cancelled.length > 0) {
        app.log.info(
          `Cancelled ${cancelled.length} pending sign prompt(s) for connection ${connectionId}: ${reason}`,
        );
      }
      for (const action of cancelled) {
        wsChannel.broadcastResolved(action.id, action.accountId);
      }
    },
  });

  const terminalManager = new TerminalManager((params) => sshTransportFactory.create(params));

  // Session-lifecycle audit writer (#184). Subscribes to TerminalManager
  // status transitions and persists open/close events to audit_session_lifecycle.
  const sessionLifecycleRepo = new DrizzleSessionLifecycleRepository(db);

  // Signing-request audit writer (#186). Subscribes to PendingActionStore
  // events and persists each request + outcome to audit_signing_requests.
  const signingRequestsRepo = new DrizzleSigningRequestsRepository(db);

  const app = await buildApp({
    config,
    terminalManager,
    endpointRepo,
    keyRepo,
    accountRepo,
    accountLifecycle,
    db,
    wsExtensions: [wsChannel],
    keyAvailability: keyWatcher,
    hydraAdmin,
    sessionLifecycleRepo,
    signingRequestsRepo,
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

  // Subscribes to terminalManager status-change events. Records sessions
  // that successfully reach `open`; failed creates (transportFactory throws)
  // are intentionally not captured today — see schema.ts comment for #184.
  const sessionLifecycleWriter = new SessionLifecycleWriter({
    terminalManager,
    repo: sessionLifecycleRepo,
    log: app.log,
  });

  // Subscribes to actionStore events and records signing requests + outcomes.
  // Detached during shutdown after the store finishes expiring pending actions.
  const signingRequestsWriter = new SigningRequestsWriter({
    actionStore,
    repo: signingRequestsRepo,
    log: app.log,
  });

  app.log.info(`WebAuthn rpId: ${config.security.rpId}`);
  app.log.info(`Trusted origins: ${config.security.trustedWebauthnOrigins.join(", ")}`);
  app.log.info(`Found ${scannedKeys.length} SSH key(s) in ${config.keyDirectory}`);
  for (const key of scannedKeys) {
    app.log.info(`  ${key.filename}: ${key.type} (${key.fingerprint})`);
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

  // Inactivity cleanup: delete accounts unused for 90+ days (admin exempt).
  // Each id flows through the same lifecycle bus the route uses, so terminals
  // and MCP transports are torn down for periodically-cleaned accounts too —
  // otherwise the leak this PR fixes recurs on a 90-day schedule (#122/#134).
  const stopCleanup = startCleanupJob(db, 90, (deletedIds) => {
    app.log.info(`Cleaned up ${deletedIds.length} inactive account(s)`);
    for (const id of deletedIds) accountLifecycle.emitDeleted(id);
  });

  const shutdown = async () => {
    stopCleanup();
    keyWatcher.stop();
    // Destroy terminals first so the writer captures the final shutdown
    // close events before we detach its listener.
    terminalManager.destroy();
    sessionLifecycleWriter.dispose();
    // Destroy actionStore before disposing the writer so the writer captures
    // the final batch of "expired" events emitted during teardown.
    actionStore.destroy();
    signingRequestsWriter.dispose();
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
