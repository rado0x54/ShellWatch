// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { EventEmitter } from "node:events";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../agent/index.js";
import { StubAccountRepository } from "../db/repositories/account-repo.js";
import { InMemoryEndpointRepository } from "../db/repositories/endpoint-repo.js";
import { InMemorySshKeyRepository } from "../db/repositories/key-repo.js";
import { createDemoEndpointsService } from "../demo-endpoints/index.js";
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
  accountId: "test-account",
  status: "open",
  createdAt: new Date(),
  lastActivityAt: new Date(),
  source: "mcp",
};

// Demo-aware MCP wiring is exercised in dedicated tests — for the general
// MCP-server tool suite we hand it empty demos + a stub account repo so the
// merge logic is effectively a no-op (showDemoEndpoints is unset).
const EMPTY_DEMO = createDemoEndpointsService([]);
const NO_OP_ACCOUNT = new StubAccountRepository();

async function setupClient(terminalManager: TerminalManager) {
  const endpointRepo = new InMemoryEndpointRepository(testEndpoints);
  const keyRepo = new InMemorySshKeyRepository(testKeys);
  const agentSession = new AgentSession({
    endpointRepo,
    demoEndpoints: EMPTY_DEMO,
    accountRepo: NO_OP_ACCOUNT,
    terminalManager,
    source: "mcp",
    accountId: testAccountId,
  });
  const mcpServer = await createMcpServer({
    agentSession,
    endpointRepo,
    demoEndpoints: EMPTY_DEMO,
    accountRepo: NO_OP_ACCOUNT,
    keyRepo,
    accountId: testAccountId,
  });
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

  // Demo-endpoint visibility/mutation behavior via MCP. Locks in the contract
  // that the toggle controls listing only, mutations are refused, and the
  // synthesized ids are resolvable via read regardless of toggle state.
  describe("shellwatch_manage_endpoints (demo endpoints)", () => {
    async function setupDemoClient(opts: { showDemoEndpoints: boolean }) {
      const endpointRepo = new InMemoryEndpointRepository(testEndpoints);
      const keyRepo = new InMemorySshKeyRepository(testKeys);
      const demoEndpoints = createDemoEndpointsService([
        {
          label: "Demo: 2048",
          address: { host: "ssh.example.com", port: 22, username: "sw-2048" },
          agentForward: false,
        },
      ]);
      const now = new Date().toISOString();
      const accountRepo: typeof NO_OP_ACCOUNT = {
        async findById() {
          return {
            id: testAccountId,
            name: "test",
            isAdmin: false,
            enabled: true,
            maxSessions: 5,
            showDemoEndpoints: opts.showDemoEndpoints,
            lastUsedAt: null,
            createdAt: now,
            updatedAt: now,
          };
        },
        async findAll() {
          return [];
        },
        async update() {},
        touchLastUsed() {},
        flushLastUsed() {},
        getAdminAccountId() {
          return null;
        },
        setAdmin() {},
        isAdmin() {
          return false;
        },
        destroy() {},
      };
      const agentSession = new AgentSession({
        endpointRepo,
        demoEndpoints,
        accountRepo,
        terminalManager: mockManager,
        source: "mcp",
        accountId: testAccountId,
      });
      const mcpServer = await createMcpServer({
        agentSession,
        endpointRepo,
        demoEndpoints,
        accountRepo,
        keyRepo,
        accountId: testAccountId,
      });
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      await mcpServer.connect(serverTransport);
      const client = new Client({ name: "test-client", version: "1.0.0" });
      await client.connect(clientTransport);
      const demoId = demoEndpoints.list(testAccountId)[0].id;
      return { client, demoId };
    }

    it("merges demo endpoints into list when the toggle is on", async () => {
      const { client, demoId } = await setupDemoClient({ showDemoEndpoints: true });
      const result = await client.callTool({
        name: "shellwatch_manage_endpoints",
        arguments: { action: "list" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      const ids = (parsed.endpoints as { id: string }[]).map((e) => e.id);
      expect(ids).toContain("dev-box");
      expect(ids).toContain(demoId);
    });

    it("omits demo endpoints from list when the toggle is off", async () => {
      const { client } = await setupDemoClient({ showDemoEndpoints: false });
      const result = await client.callTool({
        name: "shellwatch_manage_endpoints",
        arguments: { action: "list" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      const ids = (parsed.endpoints as { id: string }[]).map((e) => e.id);
      expect(ids).toEqual(["dev-box"]);
    });

    it("read resolves demo:* ids regardless of the toggle state", async () => {
      const { client, demoId } = await setupDemoClient({ showDemoEndpoints: false });
      const result = await client.callTool({
        name: "shellwatch_manage_endpoints",
        arguments: { action: "read", id: demoId },
      });
      expect(result.isError).toBeUndefined();
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.id).toBe(demoId);
      expect(parsed.host).toBe("ssh.example.com");
    });

    it("rejects update on demo:* ids", async () => {
      const { client, demoId } = await setupDemoClient({ showDemoEndpoints: true });
      const result = await client.callTool({
        name: "shellwatch_manage_endpoints",
        arguments: { action: "update", id: demoId, data: { label: "x" } },
      });
      expect(result.isError).toBe(true);
      const text = (result.content as { type: string; text: string }[])[0].text;
      expect(text).toMatch(/read-only/i);
    });

    it("rejects delete on demo:* ids", async () => {
      const { client, demoId } = await setupDemoClient({ showDemoEndpoints: true });
      const result = await client.callTool({
        name: "shellwatch_manage_endpoints",
        arguments: { action: "delete", id: demoId },
      });
      expect(result.isError).toBe(true);
      const text = (result.content as { type: string; text: string }[])[0].text;
      expect(text).toMatch(/read-only/i);
    });

    it("rejects create with a demo:* id", async () => {
      const { client } = await setupDemoClient({ showDemoEndpoints: true });
      const result = await client.callTool({
        name: "shellwatch_manage_endpoints",
        arguments: {
          action: "create",
          id: "demo:fakehash",
          data: { label: "x", host: "h", username: "u" },
        },
      });
      expect(result.isError).toBe(true);
      const text = (result.content as { type: string; text: string }[])[0].text;
      expect(text).toMatch(/read-only/i);
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
        arguments: { endpointId: "dev-box", reason: "test session" },
      });
      const content = (result.content as { type: string; text: string }[])[0].text;
      const parsed = JSON.parse(content);
      expect(parsed.sessionId).toBe("sess_abc123");
      expect(parsed.status).toBe("open");
    });

    it("threads MCP clientInfo from the initialize handshake into the trigger", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);
      const client = await setupClient(mockManager);
      await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box", reason: "audit run" },
      });
      // setupClient() advertises Client({ name: "test-client", version: "1.0.0" }).
      // The createMcpServer oninitialized hook should have cached that on the
      // AgentSession, which then surfaces it on the trigger.
      const create = mockManager.create as ReturnType<typeof vi.fn>;
      const trigger = create.mock.calls[0][2];
      expect(trigger).toMatchObject({
        kind: "mcp",
        reason: "audit run",
        mcpClientName: "test-client",
        mcpClientVersion: "1.0.0",
      });
    });

    it("sanitizes a malicious clientInfo before exposing it on the trigger", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);
      const endpointRepo = new InMemoryEndpointRepository(testEndpoints);
      const keyRepo = new InMemorySshKeyRepository(testKeys);
      const agentSession = new AgentSession({
        endpointRepo,
        demoEndpoints: EMPTY_DEMO,
        accountRepo: NO_OP_ACCOUNT,
        terminalManager: mockManager,
        source: "mcp",
        accountId: testAccountId,
      });
      const mcpServer = await createMcpServer({
        agentSession,
        endpointRepo,
        demoEndpoints: EMPTY_DEMO,
        accountRepo: NO_OP_ACCOUNT,
        keyRepo,
        accountId: testAccountId,
      });
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      await mcpServer.connect(serverTransport);
      const client = new Client({ name: "evil\nclient\x00", version: "9.9.9" });
      await client.connect(clientTransport);

      await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box", reason: "x" },
      });
      const create = mockManager.create as ReturnType<typeof vi.fn>;
      expect(create.mock.calls[0][2].mcpClientName).toBe("evilclient");
    });
  });

  describe("shellwatch_send_keys", () => {
    it("sends keys to owned session", async () => {
      (mockManager.create as ReturnType<typeof vi.fn>).mockResolvedValue(mockSession);
      const client = await setupClient(mockManager);
      await client.callTool({
        name: "shellwatch_create_session",
        arguments: { endpointId: "dev-box", reason: "test session" },
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
        arguments: { endpointId: "dev-box", reason: "test session" },
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
        arguments: { endpointId: "dev-box", reason: "test session" },
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
