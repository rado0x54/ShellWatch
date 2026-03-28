import { EventEmitter } from "node:events";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Config } from "../config/index.js";
import type { TerminalManager } from "../terminal/terminal-manager.js";
import type { TerminalSession } from "../terminal/types.js";
import { createMcpServer } from "./server.js";

const testConfig: Config = {
  servers: [
    {
      id: "dev-box",
      label: "Dev Box",
      host: "dev.example.com",
      port: 22,
      username: "ubuntu",
      privateKeyPath: "/tmp/fake.pem",
    },
  ],
  security: { allowedNetworks: ["127.0.0.1/32"] },
  notifications: { mcp: { debounceMs: 100 } },
};

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

async function setupClient(config: Config, terminalManager: TerminalManager) {
  const { server: mcpServer } = createMcpServer(config, terminalManager);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await mcpServer.connect(serverTransport);
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(clientTransport);
  return client;
}

const mockSession: TerminalSession = {
  sessionId: "sess_abc123",
  endpointId: "dev-box",
  status: "open",
  createdAt: new Date(),
  lastActivityAt: new Date(),
  source: "mcp",
};

describe("MCP Server Tools", () => {
  let mockManager: TerminalManager;

  beforeEach(() => {
    mockManager = createMockTerminalManager();
  });

  describe("shellwatch_list_endpoints", () => {
    it("returns configured endpoints", async () => {
      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({ name: "shellwatch_list_endpoints", arguments: {} });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.endpoints).toHaveLength(1);
      expect(parsed.endpoints[0].id).toBe("dev-box");
      expect(parsed.endpoints[0].privateKeyPath).toBeUndefined();
    });
  });

  describe("shellwatch_create_session", () => {
    it("creates a session", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);

      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.sessionId).toBe("sess_abc123");
      expect(parsed.status).toBe("open");
      expect(mockManager.create).toHaveBeenCalledWith("dev-box", "mcp");
    });

    it("returns error for unknown endpoint", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("Unknown endpoint: bad-id"),
      );

      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "bad-id" },
      });
      expect(result.isError).toBe(true);
    });
  });

  describe("shellwatch_list_sessions", () => {
    it("returns only owned sessions", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);
      (mockManager.listSessions as ReturnType<typeof vi.fn>).mockReturnValue([mockSession]);

      const client = await setupClient(testConfig, mockManager);
      // Create a session first so it's owned
      await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box" },
      });

      const result = await client.callTool({ name: "shellwatch_list_sessions", arguments: {} });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.sessions).toHaveLength(1);
      expect(parsed.sessions[0].sessionId).toBe("sess_abc123");
    });

    it("excludes sessions created by others", async () => {
      // Sessions exist but this client didn't create them
      (mockManager.listSessions as ReturnType<typeof vi.fn>).mockReturnValue([mockSession]);

      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({ name: "shellwatch_list_sessions", arguments: {} });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.sessions).toHaveLength(0);
    });
  });

  describe("shellwatch_send_keys", () => {
    it("sends keys to owned session", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);

      const client = await setupClient(testConfig, mockManager);
      await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box" },
      });

      const result = await client.callTool({
        name: "shellwatch_send_keys",
        arguments: { sessionId: "sess_abc123", keys: ["text:ls -la", "enter"] },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      expect(JSON.parse(content).status).toBe("sent");
      expect(mockManager.sendKeys).toHaveBeenCalledWith("sess_abc123", ["text:ls -la", "enter"]);
    });

    it("rejects send to unowned session", async () => {
      const client = await setupClient(testConfig, mockManager);
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
        data: "total 42\ndrwxr-xr-x",
        offset: 20,
        hasMore: false,
      });

      const client = await setupClient(testConfig, mockManager);
      await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box" },
      });

      const result = await client.callTool({
        name: "shellwatch_read_output",
        arguments: { sessionId: "sess_abc123" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.data).toBe("total 42\ndrwxr-xr-x");
      expect(parsed.offset).toBe(20);
    });

    it("rejects read from unowned session", async () => {
      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({
        name: "shellwatch_read_output",
        arguments: { sessionId: "sess_other" },
      });
      expect(result.isError).toBe(true);
    });
  });

  describe("shellwatch_close_session", () => {
    it("closes an owned session", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);

      const client = await setupClient(testConfig, mockManager);
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
      expect(mockManager.close).toHaveBeenCalledWith("sess_abc123");
    });

    it("rejects close of unowned session", async () => {
      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({
        name: "shellwatch_close_session",
        arguments: { sessionId: "sess_other" },
      });
      expect(result.isError).toBe(true);
    });
  });
});
