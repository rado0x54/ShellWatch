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

const BASE = "/shellwatch";

describe("Base path", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let appServer: TestAppServer;

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
    appServer = await startTestApp(sshServer, log, { basePath: BASE });
  });

  afterAll(async () => {
    await appServer?.close();
    await sshServer?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  // --- Root redirect ---

  it("GET / redirects to basePath", async () => {
    const res = await fetch(`${appServer.url}/`, { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`${BASE}/`);
  });

  // --- REST API under basePath ---

  it("GET /basePath/health returns ok", async () => {
    const res = await fetch(`${appServer.url}${BASE}/health`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe("ok");
  });

  it("GET /basePath/api/endpoints returns endpoints", async () => {
    const res = await fetch(`${appServer.url}${BASE}/api/endpoints`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.endpoints).toHaveLength(1);
    expect(data.endpoints[0].id).toBe("test-server");
  });

  it("POST + DELETE /basePath/api/sessions works", async () => {
    const createRes = await fetch(`${appServer.url}${BASE}/api/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server" }),
    });
    expect(createRes.status).toBe(200);
    const session = await createRes.json();
    expect(session.sessionId).toMatch(/^sess_/);

    const deleteRes = await fetch(`${appServer.url}${BASE}/api/sessions/${session.sessionId}`, {
      method: "DELETE",
    });
    expect(deleteRes.status).toBe(200);
  });

  // --- Unprefixed routes should 404 ---

  it("GET /api/endpoints without basePath returns 404", async () => {
    const res = await fetch(`${appServer.url}/api/endpoints`);
    expect(res.status).toBe(404);
  });

  it("GET /health without basePath returns 404", async () => {
    const res = await fetch(`${appServer.url}/health`);
    expect(res.status).toBe(404);
  });

  // --- WebSocket under basePath ---

  it("WebSocket connects at /basePath/ws", async () => {
    const ws = await connectTestWsClient(`${appServer.url}${BASE}`, log);
    try {
      const msg = await ws.waitForMessage<{ type: string; sessions: unknown[] }>(
        "sessions:changed",
      );
      expect(msg.sessions).toBeInstanceOf(Array);
    } finally {
      ws.close();
    }
  });

  it("WebSocket terminal attach works under basePath", async () => {
    // Create session via prefixed API
    const createRes = await fetch(`${appServer.url}${BASE}/api/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server" }),
    });
    const session = await createRes.json();

    const ws = await connectTestWsClient(`${appServer.url}${BASE}`, log);
    try {
      await ws.waitForMessage("sessions:changed");
      ws.send({ type: "terminal:attach", sessionId: session.sessionId });
      const msg = await ws.waitForMessage<{ type: string; status: string }>("terminal:status");
      expect(msg.status).toBe("open");
    } finally {
      ws.close();
      await fetch(`${appServer.url}${BASE}/api/sessions/${session.sessionId}`, {
        method: "DELETE",
      });
    }
  });

  // --- config.js endpoint ---

  it("GET /basePath/config.js returns basePath", async () => {
    const res = await fetch(`${appServer.url}${BASE}/config.js`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("javascript");
    const body = await res.text();
    expect(body).toContain(`"${BASE}"`);
  });
});
