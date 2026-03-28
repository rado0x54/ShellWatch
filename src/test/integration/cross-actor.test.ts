import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
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

describe("Cross-Actor: MCP ↔ WebSocket", () => {
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

  it("MCP creates session → WebSocket receives sessions:changed", async () => {
    const ws = await connectTestWsClient(appServer.url, log);
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      // Drain initial sessions:changed
      await ws.waitForMessage("sessions:changed");

      // Create session via MCP
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(result.content);

      // WebSocket should receive sessions:changed
      const msg = await ws.waitForMessage<{ type: string; sessions: { sessionId: string }[] }>(
        "sessions:changed",
      );
      expect(msg.sessions.some((s) => s.sessionId === session.sessionId)).toBe(true);

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      ws.close();
      await mcp.close();
    }
  });

  it("MCP sends input → WebSocket receives terminal:output", async () => {
    const ws = await connectTestWsClient(appServer.url, log);
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      await ws.waitForMessage("sessions:changed");

      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(result.content);

      // Attach WS to the session
      await ws.waitForMessage("sessions:changed");
      ws.send({ type: "terminal:attach", sessionId: session.sessionId });
      await ws.waitForMessage("terminal:status");

      // Send input via MCP
      await mcp.callTool("shellwatch_send_keys", {
        sessionId: session.sessionId,
        keys: ["text:cross-actor-test"],
      });

      // WebSocket should receive the echoed output
      const msg = await ws.waitForMessage<{ type: string; data: string }>("terminal:output");
      expect(msg.data).toContain("cross-actor-test");

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      ws.close();
      await mcp.close();
    }
  });

  it("MCP closes session → WebSocket receives sessions:changed and terminal:closed", async () => {
    const ws = await connectTestWsClient(appServer.url, log);
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      await ws.waitForMessage("sessions:changed");

      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(result.content);

      await ws.waitForMessage("sessions:changed");
      ws.send({ type: "terminal:attach", sessionId: session.sessionId });
      await ws.waitForMessage("terminal:status");

      // Close via MCP
      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });

      const closedMsg = await ws.waitForMessage<{ type: string; sessionId: string }>(
        "terminal:closed",
      );
      expect(closedMsg.sessionId).toBe(session.sessionId);
    } finally {
      ws.close();
      await mcp.close();
    }
  });
});

describe("Cross-Actor: HTTP ↔ MCP", () => {
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

  it("HTTP creates session → MCP list_sessions includes it", async () => {
    const createRes = await fetch(`${appServer.url}/api/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server" }),
    });
    const session = await createRes.json();

    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const listResult = await mcp.callTool("shellwatch_list_sessions");
      const parsed = JSON.parse(listResult.content);
      expect(
        parsed.sessions.some((s: { sessionId: string }) => s.sessionId === session.sessionId),
      ).toBe(true);

      await fetch(`${appServer.url}/api/sessions/${session.sessionId}`, { method: "DELETE" });
    } finally {
      await mcp.close();
    }
  });

  it("MCP creates session → HTTP GET /api/sessions includes it", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(result.content);

      const listRes = await fetch(`${appServer.url}/api/sessions`);
      const data = await listRes.json();
      expect(
        data.sessions.some((s: { sessionId: string }) => s.sessionId === session.sessionId),
      ).toBe(true);

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("HTTP closes session → MCP list_sessions no longer includes it", async () => {
    const createRes = await fetch(`${appServer.url}/api/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server" }),
    });
    const session = await createRes.json();

    await fetch(`${appServer.url}/api/sessions/${session.sessionId}`, { method: "DELETE" });

    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const listResult = await mcp.callTool("shellwatch_list_sessions");
      const parsed = JSON.parse(listResult.content);
      expect(
        parsed.sessions.find((s: { sessionId: string }) => s.sessionId === session.sessionId),
      ).toBeUndefined();
    } finally {
      await mcp.close();
    }
  });
});
