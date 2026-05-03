// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
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
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const s1 = JSON.parse(
        (
          await mcp.callTool("shellwatch_create_session", {
            endpointId: "test-server",
            reason: "integration test",
          })
        ).content,
      );
      const s2 = JSON.parse(
        (
          await mcp.callTool("shellwatch_create_session", {
            endpointId: "test-server",
            reason: "integration test",
          })
        ).content,
      );

      // Send different input to each via send_keys
      await mcp.callTool("shellwatch_send_keys", {
        sessionId: s1.sessionId,
        keys: ["text:AAA"],
      });
      await mcp.callTool("shellwatch_send_keys", {
        sessionId: s2.sessionId,
        keys: ["text:BBB"],
      });
      await new Promise((r) => setTimeout(r, 200));

      // Verify via TerminalManager directly
      const o1 = appServer.terminalManager.readOutput(s1.sessionId);
      const o2 = appServer.terminalManager.readOutput(s2.sessionId);

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
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const s1 = JSON.parse(
        (
          await mcp.callTool("shellwatch_create_session", {
            endpointId: "test-server",
            reason: "integration test",
          })
        ).content,
      );
      const s2 = JSON.parse(
        (
          await mcp.callTool("shellwatch_create_session", {
            endpointId: "test-server",
            reason: "integration test",
          })
        ).content,
      );

      await mcp.callTool("shellwatch_close_session", { sessionId: s1.sessionId });

      // s2 should still be alive
      const sendResult = await mcp.callTool("shellwatch_send_keys", {
        sessionId: s2.sessionId,
        keys: ["text:still-alive"],
      });
      expect(sendResult.isError).toBeFalsy();

      await mcp.callTool("shellwatch_close_session", { sessionId: s2.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("sessions from different actors (MCP + HTTP) coexist independently", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      // Create via MCP
      const mcpSession = JSON.parse(
        (
          await mcp.callTool("shellwatch_create_session", {
            endpointId: "test-server",
            reason: "integration test",
          })
        ).content,
      );

      // Create via HTTP
      const httpRes = await appServer.fetch(`/api/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ endpointId: "test-server", reason: "integration test" }),
      });
      const httpSession = await httpRes.json();

      // MCP only sees its own session
      const mcpList = JSON.parse((await mcp.callTool("shellwatch_list_sessions")).content).sessions;
      expect(mcpList).toHaveLength(1);
      expect(mcpList[0].sessionId).toBe(mcpSession.sessionId);

      // REST API sees both
      const httpList = await (await appServer.fetch(`/api/sessions`)).json();
      expect(httpList.sessions.length).toBeGreaterThanOrEqual(2);

      await mcp.callTool("shellwatch_close_session", { sessionId: mcpSession.sessionId });
      await appServer.fetch(`/api/sessions/${httpSession.sessionId}`, { method: "DELETE" });
    } finally {
      await mcp.close();
    }
  });
});
