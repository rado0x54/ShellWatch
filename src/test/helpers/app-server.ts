// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  type ApiKeyRepository,
} from "../../db/index.js";
import { hashApiKey } from "../../server/auth/api-key-auth.js";
import { AccountLifecycle } from "../../server/account-lifecycle.js";
import { buildApp } from "../../server/app.js";
import { createSessionCookie } from "../../server/auth/session-cookie.js";
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
  /** Live config reference — mutate to test config-driven behavior (e.g. externalUrl). */
  config: Config;
  terminalManager: TerminalManager;
  /** Session cookie header value (e.g. "sw_session=...") for authenticated requests */
  sessionCookie: string;
  /** Raw API key for MCP authentication (has `mcp` scope) */
  apiKey: string;
  /** Raw API key that exists but lacks the `mcp` scope (agent-only) */
  nonMcpApiKey: string;
  /**
   * Endpoint UUID owned by a *different* account than `apiKey`. Used by
   * cross-account isolation tests to verify the scoped lookup rejects foreign
   * endpoint ids.
   */
  foreignEndpointId: string;
  /** Account id the session cookie + apiKey are bound to. */
  accountId: string;
  /** Live reference to the in-memory API-key repo (for repo-level assertions). */
  apiKeyRepo: ApiKeyRepository;
  /** Fetch with session cookie pre-attached */
  fetch(path: string, init?: RequestInit): Promise<Response>;
  close(): Promise<void>;
}

export interface StartTestAppOptions {
  /**
   * Whether `/agent-proxy` is mounted. Drives the bearer-gate path config + the
   * OAuth shim's agent discovery surfaces. Defaults to `true` because most
   * integration tests assume both endpoints are available; opt out explicitly
   * to verify the gated-off behavior.
   */
  agentProxyEnabled?: boolean;
}

export async function startTestApp(
  sshServer: TestSshServer,
  log: TestLog,
  options: StartTestAppOptions = {},
): Promise<TestAppServer> {
  const { agentProxyEnabled = true } = options;
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

  const testCookieSecret = "test-secret-for-session-signing";
  const testAccountId = "test-account-00000000-0000-0000-0000-000000000000";
  const foreignAccountId = "foreign-account-0000-0000-0000-000000000000";
  const foreignEndpointId = "foreign-endpoint";

  const config: Config = makeTestConfig({
    keyDirectory: tmpDir,
    seedAdminEndpoints: [
      {
        label: "Test Server",
        address: { username: "testuser", host: sshServer.host, port: sshServer.port },
        agentForward: true,
      },
    ],
    security: { cookieSecret: testCookieSecret },
    agentSocket: { proxyEnabled: agentProxyEnabled },
  });

  const endpointRepo = new InMemoryEndpointRepository([
    {
      id: "test-server",
      accountId: testAccountId,
      label: "Test Server",
      host: sshServer.host,
      port: sshServer.port,
      username: "testuser",
    },
    // Endpoint owned by a different account — used to verify cross-account
    // isolation on the create-session paths.
    {
      id: foreignEndpointId,
      accountId: foreignAccountId,
      label: "Foreign Server",
      host: sshServer.host,
      port: sshServer.port,
      username: "foreign",
    },
  ]);
  const keyRepo = new InMemorySshKeyRepository([
    { id: "test-key", label: "Test Key", type: "file", publicKeyOpenSsh, fingerprint },
  ]);
  const keyProvider = new InMemoryKeyProvider([scannedKey]);

  const sshTransportFactory = new SshTransportFactory(keyRepo, keyProvider, {
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
  const terminalManager = new TerminalManager((params) => sshTransportFactory.create(params), {
    idleTimeoutMs: 60_000,
    cleanupIntervalMs: 60_000,
  });

  const testApiKey = "sw_test_000000000000000000000000";
  const testNonMcpApiKey = "sw_test_agent_00000000000000000";
  const apiKeyRepo = new InMemoryApiKeyRepository();
  await apiKeyRepo.create({
    id: "test-api-key",
    accountId: testAccountId,
    label: "Test API Key",
    keyHash: hashApiKey(testApiKey),
    keyPrefix: testApiKey.slice(0, 10),
    scopes: ["mcp"],
  });
  await apiKeyRepo.create({
    id: "test-api-key-agent-only",
    accountId: testAccountId,
    label: "Agent-only Test Key",
    keyHash: hashApiKey(testNonMcpApiKey),
    keyPrefix: testNonMcpApiKey.slice(0, 10),
    scopes: ["agent"],
  });

  const app = await buildApp({
    config,
    terminalManager,
    endpointRepo,
    keyRepo,
    accountRepo: new StubAccountRepository(),
    accountLifecycle: new AccountLifecycle(),
    apiKeyRepo,
    options: { logger: false, skipStaticFiles: true },
  });

  const sessionCookie = `sw_session=${createSessionCookie(testCookieSecret, 86400, testAccountId)}`;

  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;

  log.add("app-server", `listening on port ${port}`);

  const baseUrl = `http://127.0.0.1:${port}`;
  // externalUrl is the source of truth for discovery metadata + WWW-Authenticate
  // hints. In prod it's the config value; in tests we only know the port after
  // listen(), so patch it here — the oauth + api-key-auth modules read it
  // dynamically at request time.
  config.server.externalUrl = baseUrl;

  return {
    port,
    url: baseUrl,
    app,
    config,
    terminalManager,
    sessionCookie,
    apiKey: testApiKey,
    nonMcpApiKey: testNonMcpApiKey,
    foreignEndpointId,
    accountId: testAccountId,
    apiKeyRepo,
    fetch(path: string, init?: RequestInit): Promise<Response> {
      const headers = new Headers(init?.headers);
      headers.set("cookie", sessionCookie);
      return fetch(`${baseUrl}${path}`, { ...init, headers });
    },
    async close(): Promise<void> {
      terminalManager.destroy();
      await app.close();
      log.add("app-server", "closed");
    },
  };
}
