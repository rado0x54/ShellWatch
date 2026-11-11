// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Session lifecycle over the wire against a real sshd (#244) — file-key
 * endpoints, run against every sshd image in E2E_SSHD. Everything a browser
 * does: REST to create the endpoint + session, the human approval of the
 * file-key signature, WebSocket attach/input/resize/close, and the audit rows
 * the server persists for it all.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SSHD, SSHD_USER, sshdTargets, type SshdTarget } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import { connectWs, openSession, run, waitForPrompt, type WsClient } from "../harness/clients.js";
import { recordScenario } from "../harness/out.js";
import { logsSince, restart, sshdVersion } from "../harness/sshd.js";
import { waitFor } from "../harness/util.js";

interface AuditSessionRow {
  sessionId: string;
  endpointId: string;
  source: string;
  status: string;
  createdAt: string;
  closedAt: string | null;
  durationMs: number | null;
  closeReason: string | null;
  sourceIp: string | null;
}

interface AuditSigningRow {
  id: string;
  type: string;
  source: string;
  outcome: string | null;
  keyFingerprint: string | null;
  endpointLabel: string | null;
  endpointAddress: string | null;
}

describe.each(sshdTargets())("session lifecycle (file key) on sshd-%s", (target: SshdTarget) => {
  const scenarioName = `session-lifecycle-${target}`;
  let sc: Scenario;
  let ws: WsClient;
  let endpointId: string;
  const rec = recordScenario(scenarioName, () => sc?.server);

  beforeAll(async () => {
    sc = await bootScenario({ scenario: scenarioName, targets: [target] });
    rec.note(`target ${target}: ${sshdVersion(target)}`);
    ws = await connectWs(sc.uiToken);
    endpointId = await sc.createEndpoint({
      label: `E2E ${target}`,
      target,
      username: SSHD_USER.fileKey,
      agentForward: false,
    });
  });

  afterAll(async () => {
    ws?.close();
    await sc?.stop();
  });

  async function auditSession(sessionId: string): Promise<AuditSessionRow> {
    return waitFor(
      async () => {
        const res = await sc.api.get<{ rows: AuditSessionRow[] }>("/api/audit/sessions?limit=50");
        return res.body.rows.find((r) => r.sessionId === sessionId) ?? null;
      },
      { what: `audit row for ${sessionId}` },
    );
  }

  async function auditSigning(actionId: string): Promise<AuditSigningRow> {
    const res = await sc.api.get<AuditSigningRow>(`/api/audit/signings/${actionId}`);
    expect(res.status).toBe(200);
    return res.body;
  }

  it("creates a session via REST behind a key approval, round-trips a shell, closes on exit, and audits it", async () => {
    const since = rec.mark();
    const { response, approvals } = await openSession({
      api: sc.api,
      ws,
      identity: null,
      endpointId,
    });

    // The human was asked to approve exactly one file-key signature for this endpoint.
    expect(approvals).toHaveLength(1);
    expect(approvals[0]!.status).toBe(200);
    expect(approvals[0]!.request).toMatchObject({
      actionType: "key-approve",
      source: "endpoint-auth",
      endpointLabel: `E2E ${target}`,
      endpointAddress: `${SSHD_USER.fileKey}@${SSHD[target].host}:${SSHD[target].port}`,
      keyFingerprint: sc.server.fileKey!.fingerprint,
    });

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    const session = response.body;
    expect(session.sessionId).toMatch(/^sess_[0-9a-f]{12}$/);
    expect(session).toMatchObject({
      endpointId,
      status: "open",
      source: "ui",
      accountId: sc.accountId,
    });

    // Visible on the WS session list and via REST.
    await waitFor(() => ws.sessions().some((s) => s.sessionId === session.sessionId));
    const list = await sc.api.get<{ sessions: { sessionId: string }[] }>("/api/sessions");
    expect(list.body.sessions.map((s) => s.sessionId)).toContain(session.sessionId);

    // Attach → real PTY prompt → a real shell round-trip.
    const attached = await ws.attach(session.sessionId);
    expect(attached.status).toBe("open");
    await waitForPrompt(ws, session.sessionId);
    const out = await run(
      ws,
      session.sessionId,
      'echo "SSHC=$SSH_CONNECTION"',
      /SSHC=(\d+\.\d+\.\d+\.\d+) \d+ (\d+\.\d+\.\d+\.\d+) 22/,
    );
    expect(out).toMatch(/SSHC=\d+\.\d+\.\d+\.\d+ \d+ \d+\.\d+\.\d+\.\d+ 22/);

    // Tail via REST sees the same buffer.
    const tail = await sc.api.get<{ data: string }>(
      `/api/sessions/${session.sessionId}/tail?limit=500`,
    );
    expect(tail.status).toBe(200);
    expect(tail.body.data).toContain("SSHC=");

    // `exit` → sshd closes the channel → the session ends with the SSH hang-up reason.
    ws.type(session.sessionId, "exit\n");
    await ws.next("terminal:closed", {
      pred: (f) => f.sessionId === session.sessionId,
      timeoutMs: 15_000,
    });
    await waitFor(() => !ws.sessions().some((s) => s.sessionId === session.sessionId));
    const after = await sc.api.get<{ sessions: { sessionId: string }[] }>("/api/sessions");
    expect(after.body.sessions.find((s) => s.sessionId === session.sessionId)).toBeUndefined();

    // Audit: session row with timestamps + reason, signing row approved.
    const row = await waitFor(async () => {
      const r = await auditSession(session.sessionId);
      return r.status === "closed" ? r : null;
    });
    expect(row).toMatchObject({
      endpointId,
      source: "ui",
      status: "closed",
      closeReason: "server-hangup",
    });
    expect(row.sourceIp).toBe("127.0.0.1");
    expect(Date.parse(row.createdAt)).toBeGreaterThan(Date.parse(since) - 1000);
    expect(Date.parse(row.closedAt!)).toBeGreaterThanOrEqual(Date.parse(row.createdAt));
    expect(row.durationMs).toBeGreaterThanOrEqual(0);

    const signing = await auditSigning(approvals[0]!.request.actionId);
    expect(signing).toMatchObject({
      type: "key-approve",
      source: "endpoint-auth",
      outcome: "approved",
      keyFingerprint: sc.server.fileKey!.fingerprint,
      endpointLabel: `E2E ${target}`,
    });

    // sshd's own account of the authentication.
    const log = await logsSince(target, since);
    expect(log).toMatch(
      new RegExp(
        `Accepted publickey for ${SSHD_USER.fileKey} from .* ED25519 ${escapeRe(sc.server.fileKey!.fingerprint)}`,
      ),
    );
  });

  it("terminal:resize changes the real PTY size (stty size)", async () => {
    const { response } = await openSession({ api: sc.api, ws, identity: null, endpointId });
    expect(response.status).toBe(200);
    const sid = response.body.sessionId;
    try {
      await ws.attach(sid);
      await waitForPrompt(ws, sid);
      await run(ws, sid, "stty size", /\n24 80\s*$/m);
      ws.send({ type: "terminal:resize", sessionId: sid, cols: 120, rows: 40 });
      await run(ws, sid, "stty size", /\n40 120\s*$/m);
    } finally {
      await sc.api.delete(`/api/sessions/${sid}`);
    }
  });

  it("server-pushed output arrives without further client input", async () => {
    const { response } = await openSession({ api: sc.api, ws, identity: null, endpointId });
    expect(response.status).toBe(200);
    const sid = response.body.sessionId;
    try {
      await ws.attach(sid);
      await waitForPrompt(ws, sid);
      // The echoed command shows the unexpanded $((…)); only the background
      // job's output can produce the literal TICK-42 a second later.
      ws.type(sid, "(sleep 1; echo TICK-$((40+2))) &\n");
      await ws.waitForOutput(sid, /TICK-42/, 10_000);
    } finally {
      await sc.api.delete(`/api/sessions/${sid}`);
    }
  });

  it("runs concurrent sessions to the same host with independent I/O and close", async () => {
    const { response: a, approvals: aa } = await openSession({
      api: sc.api,
      ws,
      identity: null,
      endpointId,
    });
    const { response: b, approvals: ab } = await openSession({
      api: sc.api,
      ws,
      identity: null,
      endpointId,
    });
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(aa).toHaveLength(1);
    expect(ab).toHaveLength(1);
    const sa = a.body.sessionId;
    const sb = b.body.sessionId;
    expect(sa).not.toBe(sb);

    await ws.attach(sa);
    await ws.attach(sb);
    await waitForPrompt(ws, sa);
    await waitForPrompt(ws, sb);
    await Promise.all([
      run(ws, sa, "echo ALPHA-$((1+1))", /ALPHA-2/),
      run(ws, sb, "echo BRAVO-$((2+2))", /BRAVO-4/),
    ]);
    expect(ws.output(sa)).not.toContain("BRAVO");
    expect(ws.output(sb)).not.toContain("ALPHA");

    // Close A through REST; B keeps working. Then close B through the WS verb.
    const del = await sc.api.delete(`/api/sessions/${sa}`);
    expect(del.body).toEqual({ status: "closed" });
    await ws.next("terminal:closed", { pred: (f) => f.sessionId === sa });
    await run(ws, sb, "echo STILL-$((5+5))", /STILL-10/);

    ws.send({ type: "terminal:close", sessionId: sb });
    await ws.next("terminal:closed", { pred: (f) => f.sessionId === sb });
    const rowA = await waitFor(async () => {
      const r = await auditSession(sa);
      return r.status === "closed" ? r : null;
    });
    const rowB = await waitFor(async () => {
      const r = await auditSession(sb);
      return r.status === "closed" ? r : null;
    });
    expect(rowA.closeReason).toBe("client.ui");
    expect(rowB.closeReason).toBe("client.ws");
  });

  it("fails session creation for an unknown user with the documented error, and sshd logs the rejection", async () => {
    const since = rec.mark();
    const badEndpoint = await sc.createEndpoint({
      label: "E2E nobody",
      target,
      username: "nobody",
    });
    const { response, approvals } = await openSession({
      api: sc.api,
      ws,
      identity: null,
      endpointId: badEndpoint,
    });
    expect(response.status).toBe(400);
    expect(response.body.error).toMatch(
      /^Failed to connect to .*: SSH connection to .* failed: All configured authentication methods failed/,
    );
    // sshd refused before any signature was requested — nothing for the human to approve.
    expect(approvals).toHaveLength(0);
    const log = await logsSince(target, since);
    expect(log).toMatch(/nobody/);
    expect(log).not.toMatch(/Accepted publickey/);
  });

  it.skipIf(SSHD[target].webauthnSk)(
    "fails session creation when the user has no matching authorized key (file key offered, rejected)",
    async () => {
      // On the stable image the `passkey` user has no authorized_keys at all,
      // so the file-key probe is refused and (no passkey algorithm support)
      // the passkey can't even be offered.
      const since = rec.mark();
      const ep = await sc.createEndpoint({
        label: "E2E wrong key",
        target,
        username: SSHD_USER.passkey,
      });
      const { response, approvals } = await openSession({
        api: sc.api,
        ws,
        identity: sc.identity,
        endpointId: ep,
      });
      expect(response.status).toBe(400);
      expect(response.body.error).toMatch(/All configured authentication methods failed/);
      expect(approvals).toHaveLength(0);
      const log = await logsSince(target, since);
      expect(log).not.toMatch(/Accepted publickey/);
    },
  );

  it("marks the session closed with the hang-up reason when sshd is restarted underneath it", async () => {
    const { response } = await openSession({ api: sc.api, ws, identity: null, endpointId });
    expect(response.status).toBe(200);
    const sid = response.body.sessionId;
    await ws.attach(sid);
    await waitForPrompt(ws, sid);

    await restart(target);

    await ws.next("terminal:closed", { pred: (f) => f.sessionId === sid, timeoutMs: 30_000 });
    await waitFor(() => !ws.sessions().some((s) => s.sessionId === sid));
    const row = await waitFor(async () => {
      const r = await auditSession(sid);
      return r.status === "closed" ? r : null;
    });
    expect(row.closeReason).toBe("server-hangup");
    expect(row.closedAt).not.toBeNull();
  });
});

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
