import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import type { Config } from "../../config/index.js";
import { InMemoryEndpointRepository } from "../../db/repositories/endpoint-repo.js";
import { InMemorySshKeyRepository } from "../../db/repositories/key-repo.js";
import { buildApp } from "../../server/app.js";
import { TerminalManager } from "../../terminal/index.js";
import { createSshTransportFactory } from "../../transport/index.js";
import type { TestSshServer } from "./ssh-server.js";
import type { TestLog } from "./test-log.js";

export interface TestAppServer {
  port: number;
  url: string;
  app: FastifyInstance;
  terminalManager: TerminalManager;
  close(): Promise<void>;
}

export async function startTestApp(sshServer: TestSshServer, log: TestLog): Promise<TestAppServer> {
  const tmpDir = mkdtempSync(join(tmpdir(), "shellwatch-test-"));
  const keyPath = join(tmpDir, "test.pem");
  writeFileSync(keyPath, sshServer.clientPrivateKey, { mode: 0o600 });

  const config: Config = {
    keys: [{ id: "test-key", label: "Test Key", privateKeyPath: keyPath }],
    servers: [
      {
        id: "test-server",
        label: "Test Server",
        host: sshServer.host,
        port: sshServer.port,
        username: "testuser",
        keyId: "test-key",
      },
    ],
    security: { allowedNetworks: ["127.0.0.1/32", "::1/128", "::ffff:127.0.0.1/128"] },
    notifications: { mcp: { debounceMs: 50 } },
  };

  const endpointRepo = new InMemoryEndpointRepository(
    config.servers.map((s) => ({ ...s, privateKeyPath: keyPath })),
  );
  const keyRepo = new InMemorySshKeyRepository(config.keys);
  const transportFactory = createSshTransportFactory(endpointRepo);
  const terminalManager = new TerminalManager(endpointRepo, transportFactory, {
    idleTimeoutMs: 60_000,
    cleanupIntervalMs: 60_000,
  });

  const app = await buildApp(config, terminalManager, endpointRepo, keyRepo, {
    logger: false,
    skipVite: true,
  });

  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;

  log.add("app-server", `listening on port ${port}`);

  return {
    port,
    url: `http://127.0.0.1:${port}`,
    app,
    terminalManager,
    async close() {
      terminalManager.destroy();
      await app.close();
      log.add("app-server", "closed");
    },
  };
}
