import { loadConfig } from "./config/index.js";
import {
  createDatabase,
  DrizzleAccountRepository,
  DrizzleApiKeyRepository,
  DrizzleEndpointRepository,
  DrizzleSshKeyRepository,
  runMigrations,
  seedFromConfig,
} from "./db/index.js";
import { buildApp } from "./server/app.js";
import { TerminalManager } from "./terminal/index.js";
import { KeyDirectoryWatcher, SshTransportFactory } from "./transport/index.js";
import { SigningBridge, WebAuthnSshAgent } from "./webauthn/index.js";

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

  // Look up WebAuthn credential IDs for the agent
  const { webauthnCredentials: webauthnTable } = await import("./db/schema.js");
  const { eq } = await import("drizzle-orm");

  // Late-binding logger — set after buildApp(), but only used at session time
  const agentLog: { current?: { error(msg: string): void } } = {};

  const sshTransportFactory = new SshTransportFactory(endpointRepo, keyRepo, keyWatcher, {
    createWebAuthnAgent: (keys, rpId) => {
      if (!signingBridge.hasClients) {
        return null;
      }
      // Enrich keys with their actual WebAuthn credential IDs
      const enrichedKeys = keys.map((k) => {
        const row = db
          .select({ credentialId: webauthnTable.credentialId })
          .from(webauthnTable)
          .where(eq(webauthnTable.id, k.id))
          .get();
        return {
          ...k,
          webauthnCredentialId: row?.credentialId ?? k.id,
        };
      });
      const agent = new WebAuthnSshAgent(
        enrichedKeys,
        rpId,
        (request) => {
          signingBridge.handleSignRequest(request);
        },
        agentLog.current,
      );
      const agentId = `agent_${Date.now()}`;
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

  const shutdown = async () => {
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
