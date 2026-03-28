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

  it("lists endpoints", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const result = await mcp.callTool("shellwatch_list_endpoints");
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
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const result = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
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
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const createResult = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
      });
      const session = JSON.parse(createResult.content);

      const listResult = await mcp.callTool("shellwatch_list_sessions");
      const parsed = JSON.parse(listResult.content);
      expect(parsed.sessions.length).toBeGreaterThanOrEqual(1);
      const found = parsed.sessions.find(
        (s: { sessionId: string }) => s.sessionId === session.sessionId,
      );
      expect(found).toBeDefined();
      expect(found.source).toBe("mcp");

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("exec runs a command and returns output with exit code", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const session = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
      );

      const execResult = await mcp.callTool("shellwatch_exec", {
        sessionId: session.sessionId,
        command: "echo hello-exec-test",
      });
      const parsed = JSON.parse(execResult.content);
      expect(parsed.output).toContain("hello-exec-test");
      expect(parsed.exitCode).toBe(0);
      expect(parsed.timedOut).toBe(false);
      expect(parsed.durationMs).toBeGreaterThanOrEqual(0);

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("send_keys sends control sequences", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const session = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
      );

      const result = await mcp.callTool("shellwatch_send_keys", {
        sessionId: session.sessionId,
        keys: ["text:hello", "enter"],
      });
      const parsed = JSON.parse(result.content);
      expect(parsed.status).toBe("sent");

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });
    } finally {
      await mcp.close();
    }
  });

  it("closes a session", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const createResult = await mcp.callTool("shellwatch_create_session", {
        endpointId: "test-server",
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

  it("full lifecycle: create → exec → close", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const session = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
      );
      expect(session.status).toBe("open");

      const exec = JSON.parse(
        (
          await mcp.callTool("shellwatch_exec", {
            sessionId: session.sessionId,
            command: "echo integration-test-complete",
          })
        ).content,
      );
      expect(exec.output).toContain("integration-test-complete");
      expect(exec.exitCode).toBe(0);

      await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId });

      const list = JSON.parse((await mcp.callTool("shellwatch_list_sessions")).content);
      expect(
        list.sessions.find((s: { sessionId: string }) => s.sessionId === session.sessionId),
      ).toBeUndefined();
    } finally {
      await mcp.close();
    }
  });
});
