// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Integration coverage for the WebSocket control/observer model — the messages
 * ws-flow.test.ts doesn't exercise: take-control, release-control, resize, and
 * the observer-mode input gate (#225 item 3; flagged "partially tested" in the
 * #226 review).
 *
 * Uses an MCP-created session (source "mcp"), which attaches as OBSERVER — the
 * only way to reach the take-control path (ui-source sessions auto-control on
 * attach, per ws-message-router.ts).
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import {
  connectTestWsClient,
  createTestLog,
  createTestMcpClient,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestMcpClient,
  type TestSshServer,
  type TestWsClient,
} from "../helpers/index.js";

describe("WebSocket control/observer model", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let mcp: TestMcpClient;

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log);
    mcp = await createTestMcpClient(app.url, log, app.apiKey);
  });

  afterAll(async () => {
    await mcp?.close();
    await app?.close();
    await sshServer?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  /** Create an mcp-source session and return its id. */
  async function createMcpSession(): Promise<string> {
    const res = await mcp.callTool("shellwatch_create_session", {
      endpointId: "test-server",
      reason: "control-mode coverage",
    });
    return JSON.parse(res.content).sessionId;
  }

  async function attach(ws: TestWsClient, sessionId: string) {
    ws.send({ type: "terminal:attach", sessionId });
    await ws.waitForMessage("terminal:status");
    return ws.waitForMessage<{ mode: string }>("terminal:mode");
  }

  it("mcp session attaches as observer; input is gated until take-control", async () => {
    const sessionId = await createMcpSession();
    const ws = await connectTestWsClient(app.url, log, app.uiToken);
    try {
      const mode = await attach(ws, sessionId);
      expect(mode.mode).toBe("observer");

      // Input in observer mode → error, not forwarded.
      ws.send({ type: "terminal:input", sessionId, data: "should-be-blocked" });
      const err = await ws.waitForMessage<{ message: string }>("error");
      expect(err.message).toMatch(/observer/i);

      // Take control → mode flips, input now reaches the shell and echoes back.
      ws.send({ type: "terminal:take-control", sessionId });
      const ctl = await ws.waitForMessage<{ mode: string }>("terminal:mode");
      expect(ctl.mode).toBe("control");

      ws.send({ type: "terminal:input", sessionId, data: "ws-control-echo" });
      const out = await ws.waitForMessage<{ data: string }>("terminal:output");
      expect(out.data).toContain("ws-control-echo");
    } finally {
      ws.close();
      await mcp.callTool("shellwatch_close_session", { sessionId });
    }
  });

  it("release-control returns to observer and re-gates input", async () => {
    const sessionId = await createMcpSession();
    const ws = await connectTestWsClient(app.url, log, app.uiToken);
    try {
      await attach(ws, sessionId);
      ws.send({ type: "terminal:take-control", sessionId });
      expect((await ws.waitForMessage<{ mode: string }>("terminal:mode")).mode).toBe("control");

      ws.send({ type: "terminal:release-control", sessionId });
      expect((await ws.waitForMessage<{ mode: string }>("terminal:mode")).mode).toBe("observer");

      // Back in observer → input gated again.
      ws.send({ type: "terminal:input", sessionId, data: "blocked-again" });
      const err = await ws.waitForMessage<{ message: string }>("error");
      expect(err.message).toMatch(/observer/i);
    } finally {
      ws.close();
      await mcp.callTool("shellwatch_close_session", { sessionId });
    }
  });

  it("resize is silent — no error frame — in both observer and control mode", async () => {
    const sessionId = await createMcpSession();
    const ws = await connectTestWsClient(app.url, log, app.uiToken);
    try {
      await attach(ws, sessionId);

      // Observer resize is a no-op — deliberately asymmetric with input (which
      // errors), because resize fires on every browser layout change. No frame back.
      ws.send({ type: "terminal:resize", sessionId, cols: 120, rows: 40 });
      expect(await ws.collectMessages("error", 150)).toHaveLength(0);

      ws.send({ type: "terminal:take-control", sessionId });
      await ws.waitForMessage("terminal:mode");

      // Control resize is also silent (no ack, no error). We assert only the
      // protocol contract (no frame emitted) — not the SSH server's window-change
      // behavior, which is out of scope for the WS protocol.
      ws.send({ type: "terminal:resize", sessionId, cols: 100, rows: 30 });
      expect(await ws.collectMessages("error", 150)).toHaveLength(0);
    } finally {
      ws.close();
      await mcp.callTool("shellwatch_close_session", { sessionId });
    }
  });
});
