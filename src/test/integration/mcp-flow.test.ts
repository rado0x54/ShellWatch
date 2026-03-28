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

  it("send_keys sends input and read_output returns echoed data", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const session = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
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
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const session = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
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

  it("full lifecycle: create → send_keys → read_output → close", async () => {
    const mcp = await createTestMcpClient(appServer.url, log);
    try {
      const session = JSON.parse(
        (await mcp.callTool("shellwatch_create_session", { endpointId: "test-server" })).content,
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
});
