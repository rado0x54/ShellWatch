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

describe("Error Scenarios", () => {
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

  describe("MCP errors", () => {
    it("create session with unknown endpoint returns error", async () => {
      const mcp = await createTestMcpClient(appServer.url, log);
      try {
        const result = await mcp.callTool("shellwatch_create_session", {
          endpointId: "nonexistent",
        });
        expect(result.isError).toBe(true);
        expect(result.content).toContain("Unknown endpoint");
      } finally {
        await mcp.close();
      }
    });

    it("send input to nonexistent session returns error", async () => {
      const mcp = await createTestMcpClient(appServer.url, log);
      try {
        const result = await mcp.callTool("shellwatch_send_input", {
          sessionId: "sess_nonexistent",
          input: "data",
        });
        expect(result.isError).toBe(true);
        expect(result.content).toContain("not found");
      } finally {
        await mcp.close();
      }
    });

    it("get output from nonexistent session returns error", async () => {
      const mcp = await createTestMcpClient(appServer.url, log);
      try {
        const result = await mcp.callTool("shellwatch_get_output", {
          sessionId: "sess_nonexistent",
        });
        expect(result.isError).toBe(true);
        expect(result.content).toContain("not found");
      } finally {
        await mcp.close();
      }
    });

    it("close nonexistent session returns error", async () => {
      const mcp = await createTestMcpClient(appServer.url, log);
      try {
        const result = await mcp.callTool("shellwatch_close_session", {
          sessionId: "sess_nonexistent",
        });
        expect(result.isError).toBe(true);
        expect(result.content).toContain("not found");
      } finally {
        await mcp.close();
      }
    });
  });

  describe("HTTP errors", () => {
    it("create session when SSH server is unreachable returns 400", async () => {
      // Create an app pointing to a closed SSH server
      const deadSshServer = await startTestSshServer(log);
      const deadPort = deadSshServer.port;
      await deadSshServer.close();

      // Create app with config pointing to the now-dead port
      const deadApp = await startTestApp({ ...deadSshServer, port: deadPort }, log);

      try {
        const res = await fetch(`${deadApp.url}/api/sessions`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ endpointId: "test-server" }),
        });
        expect(res.status).toBe(400);
      } finally {
        await deadApp.close();
      }
    });
  });

  describe("WebSocket errors", () => {
    it("attach to nonexistent session returns error message", async () => {
      const ws = await connectTestWsClient(appServer.url, log);
      try {
        await ws.waitForMessage("sessions:changed");
        ws.send({ type: "terminal:attach", sessionId: "sess_nonexistent" });
        const msg = await ws.waitForMessage<{ type: string; message: string }>("error");
        expect(msg.message).toContain("not found");
      } finally {
        ws.close();
      }
    });
  });
});
