/**
 * Integration tests for the SSH agent proxy WebSocket endpoint.
 *
 * Uses ssh2's AgentProtocol in client mode to verify the protocol
 * round-trip over WebSocket.
 */

import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it, beforeAll, afterAll } from "vitest";
import ssh2 from "ssh2";
import WebSocket from "ws";
import { type Config, securityFieldDefaults, serverDefaults } from "../../config/index.js";
import { StubAccountRepository } from "../../db/repositories/account-repo.js";
import { InMemoryApiKeyRepository } from "../../db/repositories/api-key-repo.js";
import { InMemoryEndpointRepository } from "../../db/repositories/endpoint-repo.js";
import { InMemorySshKeyRepository } from "../../db/repositories/key-repo.js";
import { hashApiKey } from "../../server/auth/api-key-auth.js";
import { buildApp } from "../../server/app.js";
import { TerminalManager } from "../../terminal/index.js";
import { InMemoryKeyProvider } from "../../transport/key-directory-watcher.js";
import type { ScannedKey } from "../../transport/key-scanner.js";
import { SshTransportFactory } from "../../transport/ssh-transport-factory.js";
import type { FastifyInstance } from "fastify";

const { utils } = ssh2;

// AgentProtocol from ssh2 runtime
const AgentProtocol = (ssh2 as Record<string, unknown>).AgentProtocol as new (
  isClient: boolean,
) => NodeJS.ReadWriteStream & {
  getIdentities(cb: (err: Error | null, keys?: unknown[]) => void): void;
  sign(
    pubKey: unknown,
    data: Buffer,
    options: { hash?: string },
    cb: (err: Error | null, sig?: Buffer) => void,
  ): void;
  destroy(): void;
};

// Generate a test RSA key pair for file-based key testing
const testKeyPair = utils.generateKeyPairSync("rsa", { bits: 2048 });
const testPrivateKey = testKeyPair.private;
const testParsed = utils.parseKey(testPrivateKey)!;
if (testParsed instanceof Error) throw testParsed;
const testPubBuf = testParsed.getPublicSSH();
const testFingerprint = `SHA256:${createHash("sha256").update(testPubBuf).digest("base64url")}`;
const testPublicKeyOpenSsh = `${testParsed.type} ${testPubBuf.toString("base64")}`;

describe("agent-proxy WebSocket endpoint", () => {
  let app: FastifyInstance;
  let port: number;
  const testApiKey = "sw_test_agent_proxy_key_00000000";
  const testAccountId = "agent-test-account";

  beforeAll(async () => {
    const scannedKey: ScannedKey = {
      filename: "test-key.pem",
      path: "/tmp/test-key.pem",
      type: testParsed.type,
      publicKeyOpenSsh: testPublicKeyOpenSsh,
      fingerprint: testFingerprint,
      privateKeyContent: testPrivateKey,
    };

    const config: Config = {
      keyDirectory: "/tmp",
      seedAdminEndpoints: [],
      server: { ...serverDefaults },
      security: {
        ...securityFieldDefaults,
        rpId: "localhost",
        trustedWebauthnOrigins: ["http://localhost"],
        cookieSecret: "test-secret",
        allowedNetworks: ["127.0.0.1/32", "::1/128", "::ffff:127.0.0.1/128"],
      },
      notifications: { mcp: { debounceMs: 50 } },
      agentSocket: { proxyEnabled: true },
    };

    const endpointRepo = new InMemoryEndpointRepository([]);
    const keyRepo = new InMemorySshKeyRepository([
      {
        id: "test-key",
        label: "Test Key",
        type: "file",
        publicKey: testPublicKeyOpenSsh,
        fingerprint: testFingerprint,
      },
    ]);

    const keyProvider = new InMemoryKeyProvider([scannedKey]);
    // Extend with getAvailableKeys for agent handler
    const extendedKeyProvider = Object.assign(keyProvider, {
      getAvailableKeys: () => [scannedKey],
    });

    const sshTransportFactory = new SshTransportFactory(endpointRepo, keyRepo, keyProvider, {
      rpId: "localhost",
    });
    const terminalManager = new TerminalManager(endpointRepo, (id) =>
      sshTransportFactory.create(id),
    );

    const apiKeyRepo = new InMemoryApiKeyRepository();
    await apiKeyRepo.create({
      id: randomUUID(),
      accountId: testAccountId,
      label: "Agent Test Key",
      keyHash: hashApiKey(testApiKey),
      keyPrefix: testApiKey.slice(0, 10),
      scopes: ["agent"],
    });

    // Key with mcp scope only (should NOT grant agent access)
    await apiKeyRepo.create({
      id: randomUUID(),
      accountId: testAccountId,
      label: "MCP Only Key",
      keyHash: hashApiKey("sw_mcp_only_key_00000000000000000"),
      keyPrefix: "sw_mcp_on",
      scopes: ["mcp"],
    });

    // Key with no relevant scope
    await apiKeyRepo.create({
      id: randomUUID(),
      accountId: testAccountId,
      label: "No Scope Key",
      keyHash: hashApiKey("sw_no_scope_key_0000000000000000"),
      keyPrefix: "sw_no_sco",
      scopes: ["readonly"],
    });

    app = await buildApp({
      config,
      terminalManager,
      endpointRepo,
      keyRepo,
      accountRepo: new StubAccountRepository(),
      apiKeyRepo,
      options: { logger: false, skipStaticFiles: true },
      agentProxy: {
        keyProvider: extendedKeyProvider,
      },
    });

    await app.listen({ port: 0, host: "127.0.0.1" });
    const addr = app.server.address();
    port = typeof addr === "object" && addr ? addr.port : 0;
  });

  afterAll(async () => {
    await app.close();
  });

  function connectWs(apiKey: string): Promise<WebSocket> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/agent-proxy`, {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      ws.on("open", () => resolve(ws));
      ws.on("error", reject);
    });
  }

  it("rejects connections without API key", async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/agent-proxy`);
    const code = await new Promise<number>((resolve) => {
      ws.on("close", (code) => resolve(code));
    });
    expect(code).toBe(4001);
  });

  it("rejects connections with invalid API key", async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/agent-proxy`, {
      headers: { Authorization: "Bearer sw_invalid_key_000000000000000" },
    });
    const code = await new Promise<number>((resolve) => {
      ws.on("close", (code) => resolve(code));
    });
    expect(code).toBe(4001);
  });

  it("rejects connections with insufficient scope", async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/agent-proxy`, {
      headers: { Authorization: "Bearer sw_no_scope_key_0000000000000000" },
    });
    const code = await new Promise<number>((resolve) => {
      ws.on("close", (code) => resolve(code));
    });
    expect(code).toBe(4003);
  });

  it("rejects mcp-only keys (agent scope required)", async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/agent-proxy`, {
      headers: { Authorization: "Bearer sw_mcp_only_key_00000000000000000" },
    });
    const code = await new Promise<number>((resolve) => {
      ws.on("close", (code) => resolve(code));
    });
    expect(code).toBe(4003);
  });

  it("returns identities via agent protocol over WebSocket", async () => {
    const ws = await connectWs(testApiKey);

    // Create client-mode AgentProtocol and wire it to the WebSocket
    const client = new AgentProtocol(true);

    // WS → client protocol
    ws.on("message", (data: Buffer) => {
      client.write(data);
    });

    // client protocol → WS
    client.on("data", (chunk: Buffer) => {
      ws.send(chunk);
    });

    const keys = await new Promise<unknown[]>((resolve, reject) => {
      client.getIdentities((err, keys) => {
        if (err) reject(err);
        else resolve(keys ?? []);
      });
    });

    expect(keys.length).toBe(1);
    // The key should be a parsed key object with getPublicSSH
    const key = keys[0] as { getPublicSSH(): Buffer };
    expect(key.getPublicSSH().equals(testPubBuf)).toBe(true);

    client.destroy();
    ws.close();
  });

  it("signs data with file key via agent protocol over WebSocket", async () => {
    const ws = await connectWs(testApiKey);

    const client = new AgentProtocol(true);
    ws.on("message", (data: Buffer) => client.write(data));
    client.on("data", (chunk: Buffer) => ws.send(chunk));

    // First get identities to get the parsed key
    const keys = await new Promise<unknown[]>((resolve, reject) => {
      client.getIdentities((err, keys) => {
        if (err) reject(err);
        else resolve(keys ?? []);
      });
    });

    expect(keys.length).toBe(1);

    // Sign some test data
    const testData = Buffer.from("test data to sign");
    const signature = await new Promise<Buffer>((resolve, reject) => {
      client.sign(keys[0], testData, {}, (err, sig) => {
        if (err) reject(err);
        else resolve(sig!);
      });
    });

    expect(Buffer.isBuffer(signature)).toBe(true);
    expect(signature.length).toBeGreaterThan(0);

    // Verify the signature is valid
    const verified = testParsed.verify(testData, signature);
    expect(verified).toBe(true);

    client.destroy();
    ws.close();
  });
});
