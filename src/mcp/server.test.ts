import { EventEmitter } from "node:events";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../agent/index.js";
import { InMemoryEndpointRepository } from "../db/repositories/endpoint-repo.js";
import { InMemorySshKeyRepository } from "../db/repositories/key-repo.js";
import type { TerminalManager } from "../terminal/terminal-manager.js";
import type { TerminalSession } from "../terminal/types.js";
import { createMcpServer } from "./server.js";

const testAccountId = "test-account";

const testEndpoints = [
  {
    id: "dev-box",
    accountId: testAccountId,
    label: "Dev Box",
    host: "dev.example.com",
    port: 22,
    username: "ubuntu",
    keyId: "key-1",
  },
];

const testKeys = [
  {
    id: "key-1",
    label: "Test Key",
    type: "file",
    publicKey: "ssh-ed25519 AAAA...",
    fingerprint: "SHA256:test123",
  },
];

function createMockTerminalManager() {
  const emitter = new EventEmitter();
  return Object.assign(emitter, {
    create: vi.fn(),
    sendInput: vi.fn(),
    sendKeys: vi.fn(),
    readOutput: vi.fn(),
    resize: vi.fn(),
    listSessions: vi.fn().mockReturnValue([]),
    getSession: vi.fn(),
    close: vi.fn(),
    destroy: vi.fn(),
  }) as unknown as TerminalManager;
}

const mockSession: TerminalSession = {
  sessionId: "sess_abc123",
  endpointId: "dev-box",
  status: "open",
  createdAt: new Date(),
  lastActivityAt: new Date(),
  source: "mcp",
};

async function setupClient(terminalManager: TerminalManager) {
  const endpointRepo = new InMemoryEndpointRepository(testEndpoints);
  const keyRepo = new InMemorySshKeyRepository(testKeys);
  const agentSession = new AgentSession(endpointRepo, terminalManager, "mcp");
  const mcpServer = await createMcpServer(agentSession, endpointRepo, keyRepo, testAccountId);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await mcpServer.connect(serverTransport);
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(clientTransport);
  return client;
}

describe("MCP Server Tools", () => {
  let mockManager: TerminalManager;

  beforeEach(() => {
    mockManager = createMockTerminalManager();
  });

  describe("shellwatch_manage_endpoints", () => {
    it("lists endpoints", async () => {
      const client = await setupClient(mockManager);
      const result = await client.callTool({
        name: "shellwatch_manage_endpoints",
        arguments: { action: "list" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.endpoints).toHaveLength(1);
      expect(parsed.endpoints[0].id).toBe("dev-box");
      expect(parsed.endpoints[0].privateKeyPath).toBeUndefined();
    });
  });

  describe("shellwatch_manage_keys", () => {
    it("lists keys", async () => {
      const client = await setupClient(mockManager);
      const result = await client.callTool({
        name: "shellwatch_manage_keys",
        arguments: { action: "list" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.keys).toHaveLength(1);
      expect(parsed.keys[0].id).toBe("key-1");
      expect(parsed.keys[0].privateKeyPath).toBeUndefined();
    });
  });

  describe("shellwatch_create_session", () => {
    it("creates a session", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);
      const client = await setupClient(mockManager);
      const result = await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.sessionId).toBe("sess_abc123");
      expect(parsed.status).toBe("open");
    });
  });

  describe("shellwatch_send_keys", () => {
    it("sends keys to owned session", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);
      const client = await setupClient(mockManager);
      await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box" },
      });
      const result = await client.callTool({
        name: "shellwatch_send_keys",
        arguments: { sessionId: "sess_abc123", keys: ["text:ls", "enter"] },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      expect(JSON.parse(content).status).toBe("sent");
    });

    it("rejects unowned session", async () => {
      const client = await setupClient(mockManager);
      const result = await client.callTool({
        name: "shellwatch_send_keys",
        arguments: { sessionId: "sess_other", keys: ["enter"] },
      });
      expect(result.isError).toBe(true);
    });
  });

  describe("shellwatch_read_output", () => {
    it("reads output from owned session", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);
      (mockManager.readOutput as ReturnType<typeof vi.fn>).mockReturnValue({
        data: "output",
        offset: 6,
        hasMore: false,
      });
      const client = await setupClient(mockManager);
      await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box" },
      });
      const result = await client.callTool({
        name: "shellwatch_read_output",
        arguments: { sessionId: "sess_abc123" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      expect(JSON.parse(content).data).toBe("output");
    });
  });

  describe("shellwatch_close_session", () => {
    it("closes owned session", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);
      const client = await setupClient(mockManager);
      await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box" },
      });
      const result = await client.callTool({
        name: "shellwatch_close_session",
        arguments: { sessionId: "sess_abc123" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      expect(JSON.parse(content).status).toBe("closed");
    });
  });
});
