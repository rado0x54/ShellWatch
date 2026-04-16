import { mkdtempSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import type { FastifyInstance } from "fastify";
import ssh2 from "ssh2";

const { utils } = ssh2;

import type { Config } from "../../config/index.js";
import { makeTestConfig } from "./test-config.js";
import {
  StubAccountRepository,
  InMemoryApiKeyRepository,
  InMemoryEndpointRepository,
  InMemorySshKeyRepository,
} from "../../db/index.js";
import type { ShellWatchDB } from "../../db/connection.js";
import { accounts, webauthnCredentials } from "../../db/schema.js";
import { hashApiKey } from "../../server/auth/api-key-auth.js";
import { buildApp } from "../../server/app.js";
import { ACCESS_COOKIE_NAME } from "../../oauth/index.js";
import { TerminalManager } from "../../terminal/index.js";
import { InMemoryKeyProvider } from "../../transport/key-directory-watcher.js";
import type { ScannedKey } from "../../transport/key-scanner.js";
import { SshTransportFactory } from "../../transport/ssh-transport-factory.js";
import { sha256Fingerprint } from "../../webauthn/fingerprint.js";
import { buildFileKeyEntry, CompositeSshAgent } from "../../webauthn/index.js";
import type { TestSshServer } from "./ssh-server.js";
import type { TestLog } from "./test-log.js";

export interface TestAppServer {
  port: number;
  url: string;
  app: FastifyInstance;
  terminalManager: TerminalManager;
  /** Session cookie header value (e.g. "sw_session=...") for authenticated requests */
  sessionCookie: string;
  /** Raw API key for MCP authentication */
  apiKey: string;
  /** Fetch with session cookie pre-attached */
  fetch(path: string, init?: RequestInit): Promise<Response>;
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
  const fingerprint = sha256Fingerprint(pubKeyBuf);
  const publicKeyOpenSsh = `${parsed.type} ${pubKeyBuf.toString("base64")}`;

  const scannedKey: ScannedKey = {
    filename: "test-key.pem",
    path: keyPath,
    type: parsed.type,
    publicKeyOpenSsh,
    fingerprint,
    privateKeyContent: sshServer.clientPrivateKey,
  };

  const testCookieSecret = "test-secret-for-session-signing-32chars";
  const testAccountId = "test-account-00000000-0000-0000-0000-000000000000";

  const config: Config = makeTestConfig({
    keyDirectory: tmpDir,
    seedAdminEndpoints: [
      {
        label: "Test Server",
        address: { username: "testuser", host: sshServer.host, port: sshServer.port },
      },
    ],
    security: { cookieSecret: testCookieSecret },
  });

  // Real :memory: SQLite so the OAuth Provider has somewhere to write.
  // We also seed a stand-in account + credential so the auth-gate
  // treats the system as post-onboarding (i.e. require session) —
  // matching the old helper's behaviour where `db=null` defaulted
  // `hasPasskeys` to `true`. Without this the gate would bootstrap-pass
  // every request and the sessionCookie would be ignored entirely.
  const sqlite = new Database(":memory:");
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  const db = drizzle(sqlite, { schema: {} }) as unknown as ShellWatchDB;
  migrate(db, { migrationsFolder: resolve(import.meta.dirname, "../../../drizzle") });

  const nowIso = new Date().toISOString();
  db.insert(accounts)
    .values({
      id: testAccountId,
      name: "Test Account",
      enabled: true,
      maxSessions: 5,
      agentForward: false,
      createdAt: nowIso,
      updatedAt: nowIso,
    })
    .run();
  db.insert(webauthnCredentials)
    .values({
      id: "test-credential",
      accountId: testAccountId,
      credentialId: "test-credential-id",
      publicKey: Buffer.from(""),
      counter: 0,
      label: "Test Passkey",
      revoked: false,
      createdAt: nowIso,
    })
    .run();

  const endpointRepo = new InMemoryEndpointRepository([
    {
      id: "test-server",
      accountId: testAccountId,
      label: "Test Server",
      host: sshServer.host,
      port: sshServer.port,
      username: "testuser",
    },
  ]);
  const keyRepo = new InMemorySshKeyRepository([
    { id: "test-key", label: "Test Key", type: "file", publicKey: publicKeyOpenSsh, fingerprint },
  ]);
  const keyProvider = new InMemoryKeyProvider([scannedKey]);

  const sshTransportFactory = new SshTransportFactory(endpointRepo, keyRepo, keyProvider, {
    rpId: "localhost",
    createAgent: ({ fileKeys }) => {
      const fileKeyEntries = fileKeys
        .map((fk) => buildFileKeyEntry(fk.privateKey))
        .filter((e) => e !== null);
      if (fileKeyEntries.length === 0) return null;
      const agent = new CompositeSshAgent({
        passkeys: [],
        fileKeys: fileKeyEntries,
        rpId: "localhost",
        onSignRequest: () => {},
      });
      return { agent, cleanup: () => agent.destroy() };
    },
    isAdmin: () => true,
  });
  const terminalManager = new TerminalManager(
    endpointRepo,
    (params) => sshTransportFactory.create(params),
    {
      idleTimeoutMs: 60_000,
      cleanupIntervalMs: 60_000,
    },
  );

  const testApiKey = "sw_test_000000000000000000000000";
  const apiKeyRepo = new InMemoryApiKeyRepository();
  await apiKeyRepo.create({
    id: "test-api-key",
    accountId: testAccountId,
    label: "Test API Key",
    keyHash: hashApiKey(testApiKey),
    keyPrefix: testApiKey.slice(0, 10),
    scopes: ["mcp"],
  });

  const app = await buildApp({
    config,
    terminalManager,
    endpointRepo,
    keyRepo,
    accountRepo: new StubAccountRepository(),
    apiKeyRepo,
    db,
    options: { logger: false, skipStaticFiles: true },
  });

  // Mint a real first-party OAuth token via the app's wired-up minter
  // and hand it back as a cookie string. Tests that exercise the UI
  // session path drive through this; tests that only hit /mcp ignore
  // it and use `apiKey` instead.
  if (!app.oauth) {
    throw new Error("test app: OAuth not registered; cannot mint session cookie");
  }
  const tokens = await app.oauth.minter.mint({
    accountId: testAccountId,
    audience: config.server.externalUrl.replace(/\/$/, ""),
    scopes: ["mcp", "agent"],
  });
  const sessionCookie = `${ACCESS_COOKIE_NAME}=${encodeURIComponent(tokens.accessToken)}`;

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
    apiKey: testApiKey,
    fetch(path: string, init?: RequestInit): Promise<Response> {
      const headers = new Headers(init?.headers);
      headers.set("cookie", sessionCookie);
      return fetch(`${baseUrl}${path}`, { ...init, headers });
    },
    async close(): Promise<void> {
      terminalManager.destroy();
      await app.close();
      sqlite.close();
      log.add("app-server", "closed");
    },
  };
}
