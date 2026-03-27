import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import {
  createTestLog,
  createTestMcpClient,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

describe("Concurrent Sessions", () => {
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

  it("multiple sessions on the same endpoint have independent I/O", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const s1 = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
      );
      const s2 = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
      );

      // Send different input to each
      await mcp.callTool("shellwatch_send_input", { sessionId: s1.sessionId, input: "AAA" });
      await mcp.callTool("shellwatch_send_input", { sessionId: s2.sessionId, input: "BBB" });
      await new Promise((r) => setTimeout(r, 200));

      const o1 = JSON.parse(
        (await mcp.callTool("shellwatch_get_output", { sessionId: s1.sessionId })).content,
      );
      const o2 = JSON.parse(
        (await mcp.callTool("shellwatch_get_output", { sessionId: s2.sessionId })).content,
      );

      expect(o1.data).toContain("AAA");
      expect(o1.data).not.toContain("BBB");
      expect(o2.data).toContain("BBB");
      expect(o2.data).not.toContain("AAA");

      await mcp.callTool("shellwatch_close_session", { sessionId: s1.sessionId });
      await mcp.callTool("shellwatch_close_session", { sessionId: s2.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("closing one session does not affect others", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const s1 = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
      );
      const s2 = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
      );

      await mcp.callTool("shellwatch_close_session", { sessionId: s1.sessionId });

      // s2 should still be alive
      const sendResult = await mcp.callTool("shellwatch_send_input", {
        sessionId: s2.sessionId,
        input: "still-alive",
      });
      expect(sendResult.isError).toBeFalsy();

      await mcp.callTool("shellwatch_close_session", { sessionId: s2.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("sessions from different actors (MCP + HTTP) coexist", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      // Create via MCP
      const mcpSession = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
      );

      // Create via HTTP
      const httpRes = await fetch(`${appServer.url}/api/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ endpointId: "test-server" }),
      });
      const httpSession = await httpRes.json();

      // Both should appear in MCP list
      const listResult = await mcp.callTool("shellwatch_list_sessions");
      const sessions = JSON.parse(listResult.content).sessions;
      expect(sessions.length).toBeGreaterThanOrEqual(2);
      expect(
        sessions.find((s: { sessionId: string }) => s.sessionId === mcpSession.sessionId),
      ).toBeDefined();
      expect(
        sessions.find((s: { sessionId: string }) => s.sessionId === httpSession.sessionId),
      ).toBeDefined();

      // Check sources
      const mcpFound = sessions.find(
        (s: { sessionId: string }) => s.sessionId === mcpSession.sessionId,
      );
      const httpFound = sessions.find(
        (s: { sessionId: string }) => s.sessionId === httpSession.sessionId,
      );
      expect(mcpFound.source).toBe("mcp");
      expect(httpFound.source).toBe("ui");

      await mcp.callTool("shellwatch_close_session", { sessionId: mcpSession.sessionId });
      await fetch(`${appServer.url}/api/sessions/${httpSession.sessionId}`, { method: "DELETE" });
    } finally {
      await mcp.close();
    }
  });
});
