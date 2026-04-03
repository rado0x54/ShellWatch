import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import {
  createTestLog,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

describe("REST API Flow", () => {
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

  it("GET /api/endpoints returns configured endpoints", async () => {
    const res = await appServer.fetch(`/api/endpoints`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.endpoints).toHaveLength(1);
    expect(data.endpoints[0].id).toBe("test-server");
    expect(data.endpoints[0].privateKeyPath).toBeUndefined();
  });

  it("POST /api/sessions creates a session", async () => {
    const res = await appServer.fetch(`/api/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server" }),
    });
    expect(res.status).toBe(200);
    const session = await res.json();
    expect(session.sessionId).toMatch(/^sess_/);
    expect(session.status).toBe("open");

    // Cleanup
    await appServer.fetch(`/api/sessions/${session.sessionId}`, { method: "DELETE" });
  });

  it("GET /api/sessions lists active sessions", async () => {
    const createRes = await appServer.fetch(`/api/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server" }),
    });
    const session = await createRes.json();

    const listRes = await appServer.fetch(`/api/sessions`);
    const data = await listRes.json();
    expect(
      data.sessions.some((s: { sessionId: string }) => s.sessionId === session.sessionId),
    ).toBe(true);

    await appServer.fetch(`/api/sessions/${session.sessionId}`, { method: "DELETE" });
  });

  it("DELETE /api/sessions/:id closes a session", async () => {
    const createRes = await appServer.fetch(`/api/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server" }),
    });
    const session = await createRes.json();

    const deleteRes = await appServer.fetch(`/api/sessions/${session.sessionId}`, {
      method: "DELETE",
    });
    expect(deleteRes.status).toBe(200);
    const result = await deleteRes.json();
    expect(result.status).toBe("closed");
  });

  it("POST /api/sessions with invalid endpoint returns 400", async () => {
    const res = await appServer.fetch(`/api/sessions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpointId: "nonexistent" }),
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toContain("Unknown endpoint");
  });

  it("DELETE /api/sessions/:id with unknown session returns 404", async () => {
    const res = await appServer.fetch(`/api/sessions/sess_nonexistent`, {
      method: "DELETE",
    });
    expect(res.status).toBe(404);
  });
});
