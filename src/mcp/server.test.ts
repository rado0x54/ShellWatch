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
};

function createMockTerminalManager() {
  const emitter = new EventEmitter();
  return Object.assign(emitter, {
    create: vi.fn(),
    sendInput: vi.fn(),
    sendKeys: vi.fn(),
    exec: vi.fn(),
    readOutput: vi.fn(),
    resize: vi.fn(),
    listSessions: vi.fn().mockReturnValue([]),
    getSession: vi.fn(),
    close: vi.fn(),
    destroy: vi.fn(),
  }) as unknown as TerminalManager;
}

async function setupClient(config: Config, terminalManager: TerminalManager) {
  const mcpServer = createMcpServer(config, terminalManager);
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
      const mockSession: TerminalSession = {
        sessionId: "sess_abc123",
        endpointId: "dev-box",
        status: "open",
        createdAt: new Date(),
        lastActivityAt: new Date(),
        source: "mcp",
      };
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
    it("returns active sessions", async () => {
      const sessions: TerminalSession[] = [
        {
          sessionId: "sess_1",
          endpointId: "dev-box",
          status: "open",
          createdAt: new Date("2025-01-01T00:00:00Z"),
          lastActivityAt: new Date(),
          source: "ui",
        },
      ];
      (mockManager.listSessions as ReturnType<typeof vi.fn>).mockReturnValue(sessions);

      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({
        name: "shellwatch_list_sessions",
        arguments: {},
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.sessions).toHaveLength(1);
      expect(parsed.sessions[0].sessionId).toBe("sess_1");
    });
  });

  describe("shellwatch_exec", () => {
    it("executes a command and returns result", async () => {
      (mockManager.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        output: "file1.txt\nfile2.txt",
        exitCode: 0,
        durationMs: 42,
        timedOut: false,
      });

      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({
        name: "shellwatch_exec",
        arguments: { sessionId: "sess_1", command: "ls" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.output).toBe("file1.txt\nfile2.txt");
      expect(parsed.exitCode).toBe(0);
      expect(parsed.timedOut).toBe(false);
      expect(mockManager.exec).toHaveBeenCalledWith("sess_1", "ls", 30000);
    });

    it("passes custom timeout", async () => {
      (mockManager.exec as ReturnType<typeof vi.fn>).mockResolvedValue({
        output: "",
        exitCode: 0,
        durationMs: 10,
        timedOut: false,
      });

      const client = await setupClient(testConfig, mockManager);
      await client.callTool({
        name: "shellwatch_exec",
        arguments: { sessionId: "sess_1", command: "sleep 1", timeout: 5000 },
      });
      expect(mockManager.exec).toHaveBeenCalledWith("sess_1", "sleep 1", 5000);
    });

    it("returns error for unknown session", async () => {
      (mockManager.exec as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("Terminal session not found: bad-id"),
      );

      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({
        name: "shellwatch_exec",
        arguments: { sessionId: "bad-id", command: "ls" },
      });
      expect(result.isError).toBe(true);
    });
  });

  describe("shellwatch_send_keys", () => {
    it("sends named keys", async () => {
      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({
        name: "shellwatch_send_keys",
        arguments: { sessionId: "sess_1", keys: ["ctrl+c", "enter"] },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      expect(JSON.parse(content).status).toBe("sent");
      expect(mockManager.sendKeys).toHaveBeenCalledWith("sess_1", ["ctrl+c", "enter"]);
    });

    it("returns error for unknown session", async () => {
      (mockManager.sendKeys as ReturnType<typeof vi.fn>).mockImplementation(() => {
        throw new Error("Terminal session not found: bad-id");
      });

      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({
        name: "shellwatch_send_keys",
        arguments: { sessionId: "bad-id", keys: ["enter"] },
      });
      expect(result.isError).toBe(true);
    });
  });

  describe("shellwatch_close_session", () => {
    it("closes a session", async () => {
      const client = await setupClient(testConfig, mockManager);
      const result = await client.callTool({
        name: "shellwatch_close_session",
        arguments: { sessionId: "sess_1" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      expect(JSON.parse(content).status).toBe("closed");
      expect(mockManager.close).toHaveBeenCalledWith("sess_1");
    });
  });
});
