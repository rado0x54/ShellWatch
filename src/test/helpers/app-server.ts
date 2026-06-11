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
  InMemoryEndpointRepository,
  InMemorySshKeyRepository,
} from "../../db/index.js";
import { AccountLifecycle } from "../../server/account-lifecycle.js";
import { buildApp } from "../../server/app.js";
import { createFakeHydraAdmin, type FakeHydraAdmin } from "./fake-hydra.js";
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
  /** Bearer access token with the `ui` scope — the web UI's token, for /api + /ws. */
  uiToken: string;
  /** Bearer access token that introspects with `mcp` scope (via the fake Hydra). */
  apiKey: string;
  /** Bearer access token that introspects with `agent` scope only. */
  nonMcpApiKey: string;
  /** The in-memory fake Hydra admin — register tokens / inspect created clients. */
  hydraAdmin: FakeHydraAdmin;
  /**
   * Endpoint UUID owned by a *different* account than `apiKey`. Used by
   * cross-account isolation tests to verify the scoped lookup rejects foreign
   * endpoint ids.
   */
  foreignEndpointId: string;
  /** Account id the tokens are bound to. */
  accountId: string;
  /** Fetch with the `ui` Bearer token pre-attached (the web-UI auth path). */
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
    { id: "test-key", label: "Test Key", type: "file", publicKey: publicKeyOpenSsh, fingerprint },
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

  // Bearer access tokens. The fake Hydra introspects these to principals — a
  // ui-scoped one (the web UI / account API), an mcp-scoped one, and an
  // agent-scoped one — so the bearer gate behaves exactly as with a live Hydra.
  const testUiToken = "sw_test_ui_0000000000000000000000";
  const testApiKey = "sw_test_000000000000000000000000";
  const testNonMcpApiKey = "sw_test_agent_00000000000000000";
  const hydraAdmin = createFakeHydraAdmin();
  hydraAdmin.registerToken(testUiToken, {
    sub: testAccountId,
    scope: "openid offline ui",
    client_id: "shellwatch-web",
  });
  hydraAdmin.registerToken(testApiKey, {
    sub: testAccountId,
    scope: "mcp",
    client_id: "test-mcp-client",
  });
  hydraAdmin.registerToken(testNonMcpApiKey, {
    sub: testAccountId,
    scope: "agent",
    client_id: "test-agent-client",
  });

  const app = await buildApp({
    config,
    terminalManager,
    endpointRepo,
    keyRepo,
    accountRepo: new StubAccountRepository(),
    accountLifecycle: new AccountLifecycle(),
    hydraAdmin,
    options: { logger: false, skipStaticFiles: true },
  });

  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;

  log.add("app-server", `listening on port ${port}`);

  const baseUrl = `http://127.0.0.1:${port}`;
  // externalUrl is the source of truth for discovery metadata + WWW-Authenticate
  // hints. In prod it's the config value; in tests we only know the port after
  // listen(), so patch it here — the discovery + bearer gate read it
  // dynamically at request time.
  config.server.externalUrl = baseUrl;

  return {
    port,
    url: baseUrl,
    app,
    config,
    terminalManager,
    uiToken: testUiToken,
    apiKey: testApiKey,
    nonMcpApiKey: testNonMcpApiKey,
    hydraAdmin,
    foreignEndpointId,
    accountId: testAccountId,
    fetch(path: string, init?: RequestInit): Promise<Response> {
      const headers = new Headers(init?.headers);
      headers.set("authorization", `Bearer ${testUiToken}`);
      return fetch(`${baseUrl}${path}`, { ...init, headers });
    },
    async close(): Promise<void> {
      terminalManager.destroy();
      await app.close();
      log.add("app-server", "closed");
    },
  };
}
