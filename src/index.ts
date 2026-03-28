import { loadConfig } from "./config/index.js";
import {
  createDatabase,
  DrizzleEndpointRepository,
  DrizzleSshKeyRepository,
  runMigrations,
  seedFromConfig,
} from "./db/index.js";
import { buildApp } from "./server/app.js";
import { TerminalManager } from "./terminal/index.js";
import { createSshTransportFactory, KeyStore, scanKeyDirectory } from "./transport/index.js";

const PORT = parseInt(process.env.PORT ?? "3000", 10);
const HOST = process.env.HOST ?? "0.0.0.0";

try {
  const config = loadConfig();

  // Scan key directory for available SSH keys
  const scannedKeys = scanKeyDirectory(config.keyDirectory);
  console.log(`Found ${scannedKeys.length} SSH key(s) in ${config.keyDirectory}`);
  for (const key of scannedKeys) {
    console.log(`  ${key.filename}: ${key.type} (${key.fingerprint})`);
  }

  const keyStore = new KeyStore(scannedKeys);

  // Initialize database
  const { db, close: closeDb } = createDatabase();
  runMigrations(db);
  seedFromConfig(db, config, scannedKeys);

  const endpointRepo = new DrizzleEndpointRepository(db);
  const keyRepo = new DrizzleSshKeyRepository(db);
  const transportFactory = createSshTransportFactory(endpointRepo, keyRepo, keyStore);
  const terminalManager = new TerminalManager(endpointRepo, transportFactory);

  const app = await buildApp(config, terminalManager, endpointRepo, keyRepo, db);

  const endpoints = await endpointRepo.findAll();
  console.log(`${endpoints.length} endpoint(s) in database`);

  const shutdown = async () => {
    terminalManager.destroy();
    await app.close();
    closeDb();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  await app.listen({ port: PORT, host: HOST });
  console.log(`ShellWatch server listening on http://${HOST}:${PORT}`);
  console.log(`MCP endpoint available at http://${HOST}:${PORT}/mcp`);
} catch (err) {
  console.error("Failed to start ShellWatch:", (err as Error).message);
  process.exit(1);
}
