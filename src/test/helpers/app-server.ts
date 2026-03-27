import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import type { Config } from "../../config/index.js";
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
  // Write the client private key to a temp file
  const tmpDir = mkdtempSync(join(tmpdir(), "shellwatch-test-"));
  const keyPath = join(tmpDir, "test.pem");
  writeFileSync(keyPath, sshServer.clientPrivateKey, { mode: 0o600 });

  const config: Config = {
    servers: [
      {
        id: "test-server",
        label: "Test Server",
        host: sshServer.host,
        port: sshServer.port,
        username: "testuser",
        privateKeyPath: keyPath,
      },
    ],
  };

  const transportFactory = createSshTransportFactory(config);
  const terminalManager = new TerminalManager(config, transportFactory, {
    idleTimeoutMs: 60_000,
    cleanupIntervalMs: 60_000,
  });

  const app = await buildApp(config, terminalManager, { logger: false, skipVite: true });

  // Listen on a random port
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
