import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import {
  connectTestWsClient,
  createTestLog,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

describe("WebSocket Flow", () => {
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

  async function createSessionViaApi(): Promise<string> {
    const res = await appServer.fetch(`/api/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server" }),
    });
    const session = await res.json();
    return session.sessionId;
  }

  it("receives sessions:changed on connect", async () => {
    const ws = await connectTestWsClient(appServer.url, log, appServer.sessionCookie);
    try {
      const msg = await ws.waitForMessage<{ type: string; sessions: unknown[] }>(
        "sessions:changed",
      );
      expect(msg.sessions).toBeInstanceOf(Array);
    } finally {
      ws.close();
    }
  });

  it("receives terminal:status after attach", async () => {
    const sessionId = await createSessionViaApi();
    const ws = await connectTestWsClient(appServer.url, log, appServer.sessionCookie);
    try {
      // Wait for initial sessions:changed
      await ws.waitForMessage("sessions:changed");

      ws.send({ type: "terminal:attach", sessionId });
      const msg = await ws.waitForMessage<{ type: string; status: string }>("terminal:status");
      expect(msg.status).toBe("open");
    } finally {
      ws.close();
      await appServer.fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
    }
  });

  it("receives buffered output on attach", async () => {
    const sessionId = await createSessionViaApi();

    // Send some input so the echo server puts data in the buffer
    appServer.terminalManager.sendInput(sessionId, "buffer-test");
    await new Promise((r) => setTimeout(r, 100));

    const ws = await connectTestWsClient(appServer.url, log, appServer.sessionCookie);
    try {
      await ws.waitForMessage("sessions:changed");
      ws.send({ type: "terminal:attach", sessionId });

      const msg = await ws.waitForMessage<{ type: string; data: string }>("terminal:output");
      expect(msg.data).toContain("buffer-test");
    } finally {
      ws.close();
      await appServer.fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
    }
  });

  it("sends input and receives echoed output", async () => {
    const sessionId = await createSessionViaApi();
    const ws = await connectTestWsClient(appServer.url, log, appServer.sessionCookie);
    try {
      await ws.waitForMessage("sessions:changed");
      ws.send({ type: "terminal:attach", sessionId });
      await ws.waitForMessage("terminal:status");

      // Drain any buffered output
      await new Promise((r) => setTimeout(r, 100));

      ws.send({ type: "terminal:input", sessionId, data: "ws-echo-test" });
      const msg = await ws.waitForMessage<{ type: string; data: string }>("terminal:output");
      expect(msg.data).toContain("ws-echo-test");
    } finally {
      ws.close();
      await appServer.fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
    }
  });

  it("terminal:close closes the session", async () => {
    const sessionId = await createSessionViaApi();
    const ws = await connectTestWsClient(appServer.url, log, appServer.sessionCookie);
    try {
      await ws.waitForMessage("sessions:changed");
      ws.send({ type: "terminal:attach", sessionId });
      await ws.waitForMessage("terminal:status");

      ws.send({ type: "terminal:close", sessionId });
      await ws.waitForMessage("terminal:closed");

      // Verify session is gone
      const res = await appServer.fetch(`/api/sessions`);
      const data = await res.json();
      expect(
        data.sessions.find((s: { sessionId: string }) => s.sessionId === sessionId),
      ).toBeUndefined();
    } finally {
      ws.close();
    }
  });

  it("WebSocket disconnect does NOT kill the session", async () => {
    const sessionId = await createSessionViaApi();
    const ws = await connectTestWsClient(appServer.url, log, appServer.sessionCookie);

    await ws.waitForMessage("sessions:changed");
    ws.send({ type: "terminal:attach", sessionId });
    await ws.waitForMessage("terminal:status");

    // Disconnect WebSocket
    ws.close();
    await new Promise((r) => setTimeout(r, 100));

    // Session should still be alive
    const session = appServer.terminalManager.getSession(sessionId);
    expect(session).not.toBeNull();
    expect(session?.status).toBe("open");

    await appServer.fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
  });
});
