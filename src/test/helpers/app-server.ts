import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import ssh2 from "ssh2";

const { utils } = ssh2;

import type { Config } from "../../config/index.js";
import { InMemoryEndpointRepository } from "../../db/repositories/endpoint-repo.js";
import { InMemorySshKeyRepository } from "../../db/repositories/key-repo.js";
import { buildApp } from "../../server/app.js";
import { TerminalManager } from "../../terminal/index.js";
import { InMemoryKeyProvider } from "../../transport/key-directory-watcher.js";
import type { ScannedKey } from "../../transport/key-scanner.js";
import { SshTransportFactory } from "../../transport/ssh-transport-factory.js";
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
  const keyPath = join(tmpDir, "test-key.pem");
  writeFileSync(keyPath, sshServer.clientPrivateKey, { mode: 0o600 });

  // Parse the test key to get public key and fingerprint
  const parsed = utils.parseKey(sshServer.clientPrivateKey);
  if (!parsed || parsed instanceof Error) throw new Error("Failed to parse test SSH key");
  const pubKeyBuf = parsed.getPublicSSH();
  const fingerprint = `SHA256:${createHash("sha256").update(pubKeyBuf).digest("base64url")}`;
  const publicKeyOpenSsh = `${parsed.type} ${pubKeyBuf.toString("base64")}`;

  const scannedKey: ScannedKey = {
    filename: "test-key.pem",
    path: keyPath,
    type: parsed.type,
    publicKeyOpenSsh,
    fingerprint,
    privateKeyContent: sshServer.clientPrivateKey,
  };

  const config: Config = {
    keyDirectory: tmpDir,
    seedServers: [
      {
        id: "test-server",
        label: "Test Server",
        host: sshServer.host,
        port: sshServer.port,
        username: "testuser",
      },
    ],
    security: { allowedNetworks: ["127.0.0.1/32", "::1/128", "::ffff:127.0.0.1/128"] },
    notifications: { mcp: { debounceMs: 50 } },
  };

  const endpointRepo = new InMemoryEndpointRepository(config.seedServers);
  const keyRepo = new InMemorySshKeyRepository([
    { id: "test-key", label: "Test Key", type: "file", publicKey: publicKeyOpenSsh, fingerprint },
  ]);
  const keyProvider = new InMemoryKeyProvider([scannedKey]);

  const sshTransportFactory = new SshTransportFactory(endpointRepo, keyRepo, keyProvider);
  const terminalManager = new TerminalManager(endpointRepo, (id) => sshTransportFactory.create(id), {
    idleTimeoutMs: 60_000,
    cleanupIntervalMs: 60_000,
  });

  const app = await buildApp(config, terminalManager, endpointRepo, keyRepo, null, [], null, {
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
