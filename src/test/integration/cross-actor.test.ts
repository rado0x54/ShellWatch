// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
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
    const ws = await connectTestWsClient(appServer.url, log, appServer.uiToken);
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      // Drain initial sessions:changed
      await ws.waitForMessage("sessions:changed");

      // Create session via MCP
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
        reason: "integration test",
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
    const ws = await connectTestWsClient(appServer.url, log, appServer.uiToken);
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      await ws.waitForMessage("sessions:changed");

      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
        reason: "integration test",
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
    const ws = await connectTestWsClient(appServer.url, log, appServer.uiToken);
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      await ws.waitForMessage("sessions:changed");

      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
        reason: "integration test",
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

  it("MCP creates session → HTTP GET /api/sessions includes it", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
        reason: "integration test",
      });
      const session = JSON.parse(result.content);

      // REST API sees all sessions regardless of source
      const listRes = await appServer.fetch(`/api/sessions`);
      const data = await listRes.json();
      expect(
        data.sessions.some((s: { sessionId: string }) => s.sessionId === session.sessionId),
      ).toBe(true);

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("MCP create_session rejects an endpoint owned by a different account (#130)", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: appServer.foreignEndpointId,
        reason: "phishy reason",
      });
      expect(result.isError).toBe(true);
      expect(result.content).toMatch(/Unknown endpoint/);

      // No session for this caller should have materialized.
      const list = await mcp.callTool("shellwatch_list_sessions");
      const parsed = JSON.parse(list.content);
      expect(parsed.sessions).toEqual([]);

      // Defensive: also confirm no session was registered server-side under
      // any account for the foreign endpoint id (covers the hijack path).
      const allSessions = appServer.terminalManager.listSessions();
      expect(allSessions.some((s) => s.endpointId === appServer.foreignEndpointId)).toBe(false);
    } finally {
      await mcp.close();
    }
  });

  it("MCP cannot see HTTP-created sessions", async () => {
    const createRes = await appServer.fetch(`/api/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server", reason: "integration test" }),
    });
    const session = await createRes.json();

    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      // MCP only sees its own sessions
      const listResult = await mcp.callTool("shellwatch_list_sessions");
      const parsed = JSON.parse(listResult.content);
      expect(
        parsed.sessions.find((s: { sessionId: string }) => s.sessionId === session.sessionId),
      ).toBeUndefined();

      await appServer.fetch(`/api/sessions/${session.sessionId}`, { method: "DELETE" });
    } finally {
      await mcp.close();
    }
  });
});
