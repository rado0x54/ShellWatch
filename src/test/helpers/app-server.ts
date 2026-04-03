import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import ssh2 from "ssh2";

const { utils } = ssh2;

import { type Config, securityDefaults, serverDefaults } from "../../config/index.js";
import { StubAccountRepository } from "../../db/repositories/account-repo.js";
import { InMemoryEndpointRepository } from "../../db/repositories/endpoint-repo.js";
import { InMemorySshKeyRepository } from "../../db/repositories/key-repo.js";
import { buildApp } from "../../server/app.js";
import { createSessionCookie } from "../../server/auth/session-cookie.js";
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
  /** Session cookie header value (e.g. "sw_session=...") for authenticated requests */
  sessionCookie: string;
  /** Fetch with session cookie pre-attached */
  fetch(path: string, init?: RequestInit): Promise<Response>;
  close(): Promise<void>;
}

export interface TestAppOptions {
  basePath?: string;
}

export async function startTestApp(
  sshServer: TestSshServer,
  log: TestLog,
  options: TestAppOptions = {},
): Promise<TestAppServer> {
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

  const testCookieSecret = "test-secret-for-session-signing";
  const testAccountId = "test-account-00000000-0000-0000-0000-000000000000";

  const config: Config = {
    keyDirectory: tmpDir,
    seedAdminEndpoints: [
      {
        label: "Test Server",
        address: { username: "testuser", host: sshServer.host, port: sshServer.port },
      },
    ],
    server: { ...serverDefaults, basePath: options.basePath ?? "" },
    security: {
      ...securityDefaults,
      cookieSecret: testCookieSecret,
      allowedNetworks: ["127.0.0.1/32", "::1/128", "::ffff:127.0.0.1/128"],
    },
    notifications: { mcp: { debounceMs: 50 } },
  };

  const endpointRepo = new InMemoryEndpointRepository([
    {
      id: "test-server",
      accountId: testAccountId,
      label: "Test Server",
      host: sshServer.host,
      port: sshServer.port,
      username: "testuser",
      keyId: "test-key",
    },
  ]);
  const keyRepo = new InMemorySshKeyRepository([
    { id: "test-key", label: "Test Key", type: "file", publicKey: publicKeyOpenSsh, fingerprint },
  ]);
  const keyProvider = new InMemoryKeyProvider([scannedKey]);

  const sshTransportFactory = new SshTransportFactory(endpointRepo, keyRepo, keyProvider);
  const terminalManager = new TerminalManager(
    endpointRepo,
    (id) => sshTransportFactory.create(id),
    {
      idleTimeoutMs: 60_000,
      cleanupIntervalMs: 60_000,
    },
  );

  const app = await buildApp({
    config,
    terminalManager,
    endpointRepo,
    keyRepo,
    accountRepo: new StubAccountRepository(),
    options: { logger: false, skipStaticFiles: true },
  });

  const sessionCookie = `sw_session=${createSessionCookie(testCookieSecret, 86400, testAccountId)}`;

  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;

  log.add("app-server", `listening on port ${port}`);

  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    port,
    url: baseUrl,
    app,
    terminalManager,
    sessionCookie,
    fetch(path: string, init?: RequestInit): Promise<Response> {
      const headers = new Headers(init?.headers);
      headers.set("cookie", sessionCookie);
      return fetch(`${baseUrl}${path}`, { ...init, headers });
    },
    async close() {
      terminalManager.destroy();
      await app.close();
      log.add("app-server", "closed");
    },
  };
}
