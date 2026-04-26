import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import { makeTestConfig } from "../helpers/index.js";
import {
  connectTestWsClient,
  createTestLog,
  createTestMcpClient,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

describe("Error Scenarios", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let appServer: TestAppServer;

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
    appServer = await startTestApp(sshServer, log);
  });

  afterAll(async () => {
    await appServer?.close();
    await sshServer?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  describe("MCP errors", () => {
    it("create session with unknown endpoint returns error", async () => {
      const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
      try {
        const result = await mcp.callTool("shellwatch_create_session", {
          endpointId: "nonexistent",
          reason: "integration test",
        });
        expect(result.isError).toBe(true);
        expect(result.content).toContain("Unknown endpoint");
      } finally {
        await mcp.close();
      }
    });

    it("send keys to nonexistent session returns error", async () => {
      const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
      try {
        const result = await mcp.callTool("shellwatch_send_keys", {
          sessionId: "sess_nonexistent",
          keys: ["enter"],
        });
        expect(result.isError).toBe(true);
        expect(result.content).toContain("not found");
      } finally {
        await mcp.close();
      }
    });

    it("read_output on nonexistent session returns error", async () => {
      const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
      try {
        const result = await mcp.callTool("shellwatch_read_output", {
          sessionId: "sess_nonexistent",
        });
        expect(result.isError).toBe(true);
        expect(result.content).toContain("not found");
      } finally {
        await mcp.close();
      }
    });

    it("close nonexistent session returns error", async () => {
      const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
      try {
        const result = await mcp.callTool("shellwatch_close_session", {
          sessionId: "sess_nonexistent",
        });
        expect(result.isError).toBe(true);
        expect(result.content).toContain("not found");
      } finally {
        await mcp.close();
      }
    });
  });

  describe("Key errors", () => {
    it("MCP: create session with missing key file returns error", async () => {
      // Endpoint references a key that exists in DB but has no matching file
      const { StubAccountRepository } = await import("../../db/repositories/account-repo.js");
      const { InMemoryApiKeyRepository } = await import("../../db/repositories/api-key-repo.js");
      const { InMemoryEndpointRepository } = await import("../../db/repositories/endpoint-repo.js");
      const { InMemorySshKeyRepository } = await import("../../db/repositories/key-repo.js");
      const { InMemoryKeyProvider } = await import("../../transport/key-directory-watcher.js");
      const { SshTransportFactory } = await import("../../transport/ssh-transport-factory.js");
      const { TerminalManager } = await import("../../terminal/index.js");
      const { buildApp } = await import("../../server/app.js");
      const { AccountLifecycle } = await import("../../server/account-lifecycle.js");
      const { hashApiKey } = await import("../../server/auth/api-key-auth.js");
      const { createSessionCookie } = await import("../../server/auth/session-cookie.js");

      const endpointRepo = new InMemoryEndpointRepository([
        {
          id: "no-key-ep",
          accountId: "test-account",
          label: "No Key",
          host: "localhost",
          port: 22,
          username: "test",
        },
      ]);
      const keyRepo = new InMemorySshKeyRepository([]);
      // Empty key provider — no files available
      const keyProvider = new InMemoryKeyProvider([]);
      const factory = new SshTransportFactory(keyRepo, keyProvider, {
        rpId: "localhost",
        createAgent: () => null,
      });
      const tm = new TerminalManager((params) => factory.create(params));

      const testSecret = "test-secret";
      const config = makeTestConfig({
        seedAdminEndpoints: [
          {
            label: "No Key",
            address: { username: "test", host: "localhost", port: 22 },
          },
        ],
        security: { cookieSecret: testSecret },
      });
      const testApiKey = "sw_test_error_scenario_key";
      const errorApiKeyRepo = new InMemoryApiKeyRepository();
      await errorApiKeyRepo.create({
        id: "err-api-key",
        accountId: "test-account",
        label: "Test",
        keyHash: hashApiKey(testApiKey),
        keyPrefix: testApiKey.slice(0, 10),
        scopes: ["mcp"],
      });
      const app = await buildApp({
        config,
        terminalManager: tm,
        endpointRepo,
        keyRepo,
        accountRepo: new StubAccountRepository(),
        accountLifecycle: new AccountLifecycle(),
        apiKeyRepo: errorApiKeyRepo,
        options: { logger: false, skipStaticFiles: true },
      });
      const cookie = `sw_session=${createSessionCookie(testSecret, 86400, "test-account")}`;
      await app.listen({ port: 0, host: "127.0.0.1" });
      const addr = app.server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;

      try {
        // Test via REST API
        const res = await fetch(`http://127.0.0.1:${port}/api/sessions`, {
          method: "POST",
          headers: { "Content-Type": "application/json", cookie },
          body: JSON.stringify({ endpointId: "no-key-ep" }),
        });
        expect(res.status).toBe(400);
        const body = await res.json();
        expect(body.error).toContain("No SSH keys available");

        // Test via MCP
        const { createTestMcpClient } = await import("../helpers/mcp-client.js");
        const mcp = await createTestMcpClient(`http://127.0.0.1:${port}`, log, testApiKey);
        try {
          const result = await mcp.callTool("shellwatch_create_session", {
            endpointId: "no-key-ep",
            reason: "integration test",
          });
          expect(result.isError).toBe(true);
          expect(result.content).toContain("No SSH keys available");
        } finally {
          await mcp.close();
        }
      } finally {
        tm.destroy();
        await app.close();
      }
    });
  });

  describe("HTTP errors", () => {
    it("create session when SSH server is unreachable returns 400", async () => {
      // Create an app pointing to a closed SSH server
      const deadSshServer = await startTestSshServer(log);
      const deadPort = deadSshServer.port;
      await deadSshServer.close();

      // Create app with config pointing to the now-dead port
      const deadApp = await startTestApp({ ...deadSshServer, port: deadPort }, log);

      try {
        const res = await deadApp.fetch(`/api/sessions`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ endpointId: "test-server", reason: "integration test" }),
        });
        expect(res.status).toBe(400);
      } finally {
        await deadApp.close();
      }
    });
  });

  describe("WebSocket errors", () => {
    it("attach to nonexistent session returns error message", async () => {
      const ws = await connectTestWsClient(appServer.url, log, appServer.sessionCookie);
      try {
        await ws.waitForMessage("sessions:changed");
        ws.send({ type: "terminal:attach", sessionId: "sess_nonexistent" });
        const msg = await ws.waitForMessage<{ type: string; message: string }>("error");
        expect(msg.message).toContain("not found");
      } finally {
        ws.close();
      }
    });
  });
});
