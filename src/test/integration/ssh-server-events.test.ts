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

describe("SSH Server Events", () => {
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

  it("SSH server pushes output → output buffer contains it", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(result.content);

      // Push output from the SSH server side
      sshServer.pushOutput("server-initiated-data\n");
      await new Promise((r) => setTimeout(r, 200));

      // Verify via TerminalManager directly (get_output removed from MCP)
      const output = appServer.terminalManager.readOutput(session.sessionId);
      expect(output.data).toContain("server-initiated-data");

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("SSH server pushes output → WebSocket client receives terminal:output", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    const ws = await connectTestWsClient(appServer.url, log, appServer.sessionCookie);
    try {
      await ws.waitForMessage("sessions:changed");

      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(result.content);

      await ws.waitForMessage("sessions:changed");
      ws.send({ type: "terminal:attach", sessionId: session.sessionId });
      await ws.waitForMessage("terminal:status");

      // Push output from the SSH server side
      sshServer.pushOutput("pushed-to-frontend\n");

      const msg = await ws.waitForMessage<{ type: string; data: string }>("terminal:output");
      expect(msg.data).toContain("pushed-to-frontend");

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      ws.close();
      await mcp.close();
    }
  });

  it("SSH server disconnects → session status changes to closed", async () => {
    const isolatedSshServer = await startTestSshServer(log);
    const isolatedApp = await startTestApp(isolatedSshServer, log);

    const mcp = await createTestMcpClient(isolatedApp.url, log, isolatedApp.apiKey);
    try {
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(result.content);

      isolatedSshServer.disconnectAll();
      await new Promise((r) => setTimeout(r, 200));

      const listResult = await mcp.callTool("shellwatch_list_sessions");
      const parsed = JSON.parse(listResult.content);
      const found = parsed.sessions.find(
        (s: { sessionId: string }) => s.sessionId === session.sessionId,
      );
      expect(found).toBeUndefined();
    } finally {
      await mcp.close();
      await isolatedApp.close();
      await isolatedSshServer.close();
    }
  });

  it("SSH server disconnects → WebSocket receives sessions:changed", async () => {
    const isolatedSshServer = await startTestSshServer(log);
    const isolatedApp = await startTestApp(isolatedSshServer, log);

    const ws = await connectTestWsClient(isolatedApp.url, log, isolatedApp.sessionCookie);
    const mcp = await createTestMcpClient(isolatedApp.url, log, isolatedApp.apiKey);
    try {
      await ws.waitForMessage("sessions:changed");

      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      JSON.parse(result.content);
      await ws.waitForMessage("sessions:changed");

      isolatedSshServer.disconnectAll();

      const msg = await ws.waitForMessage<{
        type: string;
        sessions: { sessionId: string; status: string }[];
      }>("sessions:changed");
      // Session should be gone or show closed/error
      for (const s of msg.sessions) {
        if (s.status === "open") {
          // If still open, it hasn't processed the disconnect yet — unexpected
          expect(s.status).not.toBe("open");
        }
      }
    } finally {
      ws.close();
      await mcp.close();
      await isolatedApp.close();
      await isolatedSshServer.close();
    }
  });
});
