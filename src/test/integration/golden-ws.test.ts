// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden characterization of the WebSocket protocol frames — the connect-time
 * `sessions:changed` snapshot and the `terminal:attach` reply sequence
 * (`terminal:status` + `terminal:mode`). Parity oracle for the Go rewrite
 * (#225 item 2). See docs/api/websocket-protocol.md for the surface.
 *
 * Ordering is made deterministic by creating the (ui-source) session first — so
 * it is fully `open` before the socket connects — then reading the single
 * snapshot the handler pushes on connect. Buffered `terminal:output` frames are
 * not goldened: the echo shell's content is non-deterministic.
 */
import { afterAll, afterEach, beforeAll, describe, it, onTestFailed } from "vitest";
import {
  connectTestWsClient,
  createTestLog,
  expectGolden,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
  type TestWsClient,
} from "../helpers/index.js";

describe("Golden: WebSocket contract", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let ws: TestWsClient;
  let sessionId: string;

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log);

    // Create a ui-source session and wait until it's fully open, so the
    // connect-time snapshot and attach reply are deterministic.
    const res = await app.fetch("/api/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ endpointId: "test-server" }),
    });
    sessionId = (await res.json()).sessionId;

    ws = await connectTestWsClient(app.url, log, app.uiToken);
  });

  afterAll(async () => {
    ws?.close();
    if (sessionId) await app.fetch(`/api/sessions/${sessionId}`, { method: "DELETE" });
    await app?.close();
    await sshServer?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  it("connect-time sessions:changed snapshot", async () => {
    const msg = await ws.waitForMessage("sessions:changed");
    expectGolden(import.meta.url, "ws-sessions-changed", msg);
  });

  it("terminal:attach reply — status then mode (ui → control)", async () => {
    ws.send({ type: "terminal:attach", sessionId });
    const status = await ws.waitForMessage("terminal:status");
    const mode = await ws.waitForMessage("terminal:mode");
    expectGolden(import.meta.url, "ws-attach-status", status);
    expectGolden(import.meta.url, "ws-attach-mode", mode);
  });
});
