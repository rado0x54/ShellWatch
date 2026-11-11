// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Idle-session janitor against a real sshd (#244). Boots its own server with a
 * tiny `sessions.idleTimeoutMinutes` so the janitor closes the session within
 * seconds; asserts the WS event, the audit reason, and that sshd saw the
 * client disconnect.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SSHD_USER, sshdTargets } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import { connectWs, openSession, waitForPrompt, type WsClient } from "../harness/clients.js";
import { recordScenario } from "../harness/out.js";
import { logsSince } from "../harness/sshd.js";
import { waitFor } from "../harness/util.js";

const target = sshdTargets()[0]!;
const IDLE_SECONDS = 3;

describe(`idle timeout on sshd-${target}`, () => {
  let sc: Scenario;
  let ws: WsClient;
  const rec = recordScenario("idle-timeout", () => sc?.server);

  beforeAll(async () => {
    sc = await bootScenario({
      scenario: "idle-timeout",
      targets: [target],
      sessions: { idleTimeoutMinutes: IDLE_SECONDS / 60, cleanupIntervalSeconds: 1 },
    });
    ws = await connectWs(sc.uiToken);
  });

  afterAll(async () => {
    ws?.close();
    await sc?.stop();
  });

  it("closes an idle session with reason idle-timeout and disconnects from sshd", async () => {
    const endpointId = await sc.createEndpoint({
      label: "E2E idle",
      target,
      username: SSHD_USER.fileKey,
    });
    const { response } = await openSession({ api: sc.api, ws, identity: null, endpointId });
    expect(response.status).toBe(200);
    const sid = response.body.sessionId;
    await ws.attach(sid);
    await waitForPrompt(ws, sid);
    const since = rec.mark();
    const quietFrom = Date.now();

    // No input, no output → the janitor must close it.
    await ws.next("terminal:closed", { pred: (f) => f.sessionId === sid, timeoutMs: 20_000 });
    expect(Date.now() - quietFrom).toBeGreaterThanOrEqual(IDLE_SECONDS * 1000 - 200);

    const row = await waitFor(async () => {
      const res = await sc.api.get<{
        rows: { sessionId: string; status: string; closeReason: string | null }[];
      }>("/api/audit/sessions");
      const r = res.body.rows.find((x) => x.sessionId === sid);
      return r?.status === "closed" ? r : null;
    });
    expect(row.closeReason).toBe("idle-timeout");

    const log = await waitFor(
      async () => {
        const l = await logsSince(target, since);
        return /(Disconnected from|Received disconnect from|Connection closed by)[^\n]*/.test(l)
          ? l
          : null;
      },
      { timeoutMs: 10_000, what: "sshd to log the disconnect" },
    );
    expect(log).toMatch(
      new RegExp(
        `(Disconnected from user ${SSHD_USER.fileKey}|Received disconnect from|Connection closed by)`,
      ),
    );
  });
});
