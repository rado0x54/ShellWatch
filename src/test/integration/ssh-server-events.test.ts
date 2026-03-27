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

  it("SSH server pushes output → MCP get_output returns it", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(result.content);

      // Push output from the SSH server side
      sshServer.pushOutput("server-initiated-data\n");
      await new Promise((r) => setTimeout(r, 200));

      const output = JSON.parse(
        (await mcp.callTool("shellwatch_get_output", { sessionId: session.sessionId })).content,
      );
      expect(output.data).toContain("server-initiated-data");

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("SSH server pushes output → WebSocket client receives terminal:output", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    const ws = await connectTestWsClient(appServer.url, log);
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
    // Use a separate SSH server so we can disconnect it without affecting other tests
    const isolatedSshServer = await startTestSshServer(log);
    const isolatedApp = await startTestApp(isolatedSshServer, log);

    const mcp = await createTestMcpClient(isolatedApp.url, log);
    try {
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(result.content);

      // Disconnect all SSH clients
      isolatedSshServer.disconnectAll();
      await new Promise((r) => setTimeout(r, 200));

      // Session should reflect closed status
      const listResult = await mcp.callTool("shellwatch_list_sessions");
      const parsed = JSON.parse(listResult.content);
      const found = parsed.sessions.find(
        (s: { sessionId: string }) => s.sessionId === session.sessionId,
      );
      // Session should be gone (closed sessions are filtered from list)
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

    const ws = await connectTestWsClient(isolatedApp.url, log);
    const mcp = await createTestMcpClient(isolatedApp.url, log);
    try {
      await ws.waitForMessage("sessions:changed");

      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(result.content);
      await ws.waitForMessage("sessions:changed");

      // Disconnect SSH server
      isolatedSshServer.disconnectAll();

      // Should receive sessions:changed reflecting the closed session
      const msg = await ws.waitForMessage<{
        type: string;
        sessions: { sessionId: string; status: string }[];
      }>("sessions:changed");
      const found = msg.sessions.find((s) => s.sessionId === session.sessionId);
      // Either the session is gone or status is closed/error
      if (found) {
        expect(["closed", "error"]).toContain(found.status);
      }
    } finally {
      ws.close();
      await mcp.close();
      await isolatedApp.close();
      await isolatedSshServer.close();
    }
  });
});
