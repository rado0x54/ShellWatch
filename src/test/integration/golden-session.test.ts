// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden characterization of the session-lifecycle REST *success* bodies:
 * create → list → tail → close. golden-http already pins the error cases
 * (404 unknown endpoint, 404 unknown-session tail); this suite pins the 200
 * envelopes the SPA actually consumes. Parity oracle for the Go rewrite (#225).
 *
 * Determinism: the session is created (ui source) and reaches `status: "open"`
 * before capture (terminalManager.create resolves on connect), so the object is
 * stable modulo sessionId/timestamps/port, which fold via the standard
 * normalizer. The tail's `data` field is raw echo-shell output — the same
 * non-deterministic content golden-ws deliberately refuses to pin — so it is
 * folded to "<OUTPUT>" here; the golden asserts the { data } envelope + 200,
 * not the bytes.
 */
import { afterAll, afterEach, beforeAll, describe, it, onTestFailed } from "vitest";
import {
  createTestLog,
  expectGolden,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

describe("Golden: session lifecycle contract", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let baseUrls: string[];
  let ports: number[];
  let sessionId: string;

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log);
    baseUrls = [app.url];
    ports = [app.port, sshServer.port];
  });

  afterAll(async () => {
    // Best-effort — the close test already removed it; ignore 404.
    if (sessionId)
      await app.fetch(`/api/sessions/${sessionId}`, { method: "DELETE" }).catch(() => {});
    await app?.close();
    await sshServer?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  function snap(name: string, path: string, status: number, body: unknown) {
    expectGolden(import.meta.url, name, { request: { path }, status, body }, { baseUrls, ports });
  }

  it("POST /api/sessions (create → open session object)", async () => {
    const res = await app.fetch("/api/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server" }),
    });
    const body = await res.json();
    sessionId = body.sessionId;
    snap("session-create", "/api/sessions", res.status, body);
  });

  it("GET /api/sessions (list — one open session)", async () => {
    const res = await app.fetch("/api/sessions");
    snap("session-list", "/api/sessions", res.status, await res.json());
  });

  it("GET /api/sessions/:id/tail (envelope; output folded)", async () => {
    const res = await app.fetch(`/api/sessions/${sessionId}/tail`);
    const body = await res.json();
    // Raw terminal bytes are environment-dependent (see golden-ws): pin the
    // { data } envelope, not the content.
    if (typeof body?.data === "string") body.data = "<OUTPUT>";
    snap("session-tail", "/api/sessions/{id}/tail", res.status, body);
  });

  it("DELETE /api/sessions/:id (close)", async () => {
    const res = await app.fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
    snap("session-close", "/api/sessions/{id}", res.status, await res.json());
  });
});
