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

describe("MCP Client Flow", () => {
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

  it("rejects API key lacking 'mcp' scope at /mcp (403)", async () => {
    // Bearer-gate enforces scope on /mcp — agent-only keys cannot call MCP tools.
    const res = await fetch(`${appServer.url}/mcp`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${appServer.nonMcpApiKey}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "initialize",
        params: { protocolVersion: "2024-11-05", capabilities: {} },
        id: 1,
      }),
    });
    expect(res.status).toBe(403);
    expect(res.headers.get("www-authenticate")).toContain("insufficient_scope");
  });

  it("lists endpoints", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const result = await mcp.callTool("shellwatch_manage_endpoints", { action: "list" });
      const parsed = JSON.parse(result.content);
      expect(parsed.endpoints).toHaveLength(1);
      expect(parsed.endpoints[0]).toMatchObject({
        id: "test-server",
        label: "Test Server",
        host: "127.0.0.1",
        username: "testuser",
      });
      expect(parsed.endpoints[0].privateKeyPath).toBeUndefined();
    } finally {
      await mcp.close();
    }
  });

  it("creates a session", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
        reason: "integration test",
      });
      const parsed = JSON.parse(result.content);
      expect(parsed.sessionId).toMatch(/^sess_/);
      expect(parsed.endpointId).toBe("test-server");
      expect(parsed.status).toBe("open");

      await mcp.callTool("shellwatch_close_session", { sessionId: parsed.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("lists sessions", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const createResult = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
        reason: "integration test",
      });
      const session = JSON.parse(createResult.content);

      const listResult = await mcp.callTool("shellwatch_list_sessions");
      const parsed = JSON.parse(listResult.content);
      expect(parsed.sessions.length).toBeGreaterThanOrEqual(1);
      const found = parsed.sessions.find(
        (s: { sessionId: string }) => s.sessionId === session.sessionId,
      );
      expect(found).toBeDefined();

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("send_keys sends input and read_output returns echoed data", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const session = JSON.parse(
        (
          await mcp.callTool("shellwatch_create_session", {
            endpointId: "test-server",
            reason: "integration test",
          })
        ).content,
      );

      // Send a command
      await mcp.callTool("shellwatch_send_keys", {
        sessionId: session.sessionId,
        keys: ["text:hello-test", "enter"],
      });

      // Wait for the echo server to respond
      await new Promise((r) => setTimeout(r, 200));

      // Read the output
      const output = JSON.parse(
        (await mcp.callTool("shellwatch_read_output", { sessionId: session.sessionId })).content,
      );
      expect(output.data).toContain("hello-test");
      expect(output.offset).toBeGreaterThan(0);

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("read_output supports incremental reads via offset", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const session = JSON.parse(
        (
          await mcp.callTool("shellwatch_create_session", {
            endpointId: "test-server",
            reason: "integration test",
          })
        ).content,
      );

      await mcp.callTool("shellwatch_send_keys", {
        sessionId: session.sessionId,
        keys: ["text:AAA", "enter"],
      });
      await new Promise((r) => setTimeout(r, 100));

      const r1 = JSON.parse(
        (await mcp.callTool("shellwatch_read_output", { sessionId: session.sessionId })).content,
      );
      expect(r1.data).toContain("AAA");
      const offset1 = r1.offset;

      await mcp.callTool("shellwatch_send_keys", {
        sessionId: session.sessionId,
        keys: ["text:BBB", "enter"],
      });
      await new Promise((r) => setTimeout(r, 100));

      const r2 = JSON.parse(
        (
          await mcp.callTool("shellwatch_read_output", {
            sessionId: session.sessionId,
            afterOffset: offset1,
          })
        ).content,
      );
      expect(r2.data).toContain("BBB");
      expect(r2.data).not.toContain("AAA");

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("closes a session", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const createResult = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
        reason: "integration test",
      });
      const session = JSON.parse(createResult.content);

      const closeResult = await mcp.callTool("shellwatch_close_session", {
        sessionId: session.sessionId,
      });
      expect(JSON.parse(closeResult.content).status).toBe("closed");

      const listResult = await mcp.callTool("shellwatch_list_sessions");
      const parsed = JSON.parse(listResult.content);
      expect(
        parsed.sessions.find((s: { sessionId: string }) => s.sessionId === session.sessionId),
      ).toBeUndefined();
    } finally {
      await mcp.close();
    }
  });

  it("full lifecycle: create → send_keys → read_output → close", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const session = JSON.parse(
        (
          await mcp.callTool("shellwatch_create_session", {
            endpointId: "test-server",
            reason: "integration test",
          })
        ).content,
      );
      expect(session.status).toBe("open");

      await mcp.callTool("shellwatch_send_keys", {
        sessionId: session.sessionId,
        keys: ["text:integration-test-complete", "enter"],
      });
      await new Promise((r) => setTimeout(r, 200));

      const output = JSON.parse(
        (await mcp.callTool("shellwatch_read_output", { sessionId: session.sessionId })).content,
      );
      expect(output.data).toContain("integration-test-complete");

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });

      const list = JSON.parse((await mcp.callTool("shellwatch_list_sessions")).content);
      expect(
        list.sessions.find((s: { sessionId: string }) => s.sessionId === session.sessionId),
      ).toBeUndefined();
    } finally {
      await mcp.close();
    }
  });

  it("receives output_available notification after sending input", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const session = JSON.parse(
        (
          await mcp.callTool("shellwatch_create_session", {
            endpointId: "test-server",
            reason: "integration test",
          })
        ).content,
      );

      await mcp.callTool("shellwatch_send_keys", {
        sessionId: session.sessionId,
        keys: ["text:notification-test", "enter"],
      });

      const notification = await mcp.waitForNotification(
        "notifications/shellwatch/output_available",
        2000,
      );
      expect(notification.params?.sessionId).toBe(session.sessionId);
      expect(typeof notification.params?.offset).toBe("number");
      expect(notification.params?.offset as number).toBeGreaterThan(0);

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("receives session_status notification on session close", async () => {
    const mcp = await createTestMcpClient(appServer.url, log, appServer.apiKey);
    try {
      const session = JSON.parse(
        (
          await mcp.callTool("shellwatch_create_session", {
            endpointId: "test-server",
            reason: "integration test",
          })
        ).content,
      );

      // Close the session — should trigger a closing/closed status notification
      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });

      const notification = await mcp.waitForNotification(
        "notifications/shellwatch/session_status",
        2000,
      );
      expect(notification.params?.sessionId).toBe(session.sessionId);
      expect(["closed", "closing"]).toContain(notification.params?.status);
    } finally {
      await mcp.close();
    }
  });
});
