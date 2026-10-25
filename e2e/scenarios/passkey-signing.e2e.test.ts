// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * The product's core claim, end to end (#244): a WebAuthn assertion produced by
 * the fake authenticator, approved through ShellWatch's pending-action flow, is
 * accepted by a real OpenSSH sshd as a `webauthn-sk-ecdsa-sha2-nistp256`
 * public-key signature. Plus deny / expiry / UV-required negatives, each
 * checked against sshd's own log.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { modernEnabled, RP_ID, SSHD_USER } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import {
  approveSignRequest,
  connectWs,
  openSession,
  run,
  waitForPrompt,
  type SignRequestFrame,
  type WsClient,
} from "../harness/clients.js";
import { WEBAUTHN_SSH_ALGORITHM } from "../harness/identity.js";
import { recordScenario } from "../harness/out.js";
import { logsSince } from "../harness/sshd.js";
import { waitFor } from "../harness/util.js";

const target = "modern" as const;

interface ActionView {
  id: string;
  type: string;
  status: string;
  credentialId?: string;
  rpId?: string;
  userVerification?: string;
  context: { source: string; endpointLabel?: string; trigger?: { kind: string } };
}

interface SigningRow {
  id: string;
  type: string;
  source: string;
  outcome: string | null;
  credentialId: string | null;
  userVerification: string | null;
  latencyMs: number | null;
}

describe.skipIf(!modernEnabled())("passkey signing against sshd-modern", () => {
  let sc: Scenario;
  let ws: WsClient;
  let endpointId: string;
  const rec = recordScenario("passkey-signing", () => sc?.server);

  beforeAll(async () => {
    sc = await bootScenario({ scenario: "passkey-signing", targets: [target] });
    ws = await connectWs(sc.uiToken);
    endpointId = await sc.createEndpoint({
      label: "E2E passkey",
      target,
      username: SSHD_USER.passkey,
      agentForward: false,
    });
  });

  afterAll(async () => {
    ws?.close();
    await sc?.stop();
  });

  const action = async (id: string) => (await sc.api.get<ActionView>(`/api/actions/${id}`)).body;
  const signing = async (id: string) =>
    (await sc.api.get<SigningRow>(`/api/audit/signings/${id}`)).body;

  it("derives the same OpenSSH authorized_keys line the UI shows for the seeded passkey", async () => {
    const res = await sc.api.get<{
      credentials: {
        credentialId: string;
        authorizedKeysEntry: string | null;
        algorithm: string;
      }[];
      sshdConfig: string;
    }>("/api/webauthn/credentials");
    expect(res.status).toBe(200);
    const cred = res.body.credentials.find((c) => c.credentialId === sc.identity.credentialId);
    expect(cred?.authorizedKeysEntry).toBe(sc.identity.openSshLine);
    expect(res.body.sshdConfig).toBe(`PubkeyAcceptedAlgorithms=+${WEBAUTHN_SSH_ALGORITHM}`);
  });

  it("authenticates to sshd with a passkey signature approved through the pending-action flow", async () => {
    const since = rec.mark();
    const { response, approvals } = await openSession({
      api: sc.api,
      ws,
      identity: sc.identity,
      endpointId,
    });

    expect(approvals).toHaveLength(1);
    const req = approvals[0]!.request;
    expect(req).toMatchObject({
      actionType: "webauthn-sign",
      source: "endpoint-auth",
      credentialId: sc.identity.credentialId,
      rpId: RP_ID,
      endpointLabel: "E2E passkey",
    });
    expect(req.deepLink).toBe(`${sc.server.url}/sign/${req.actionId}`);
    expect(approvals[0]!.status, JSON.stringify(approvals[0]!.body)).toBe(200);
    expect(approvals[0]!.body).toEqual({ redirectTo: `/session/${response.body.sessionId}` });

    expect(response.status, JSON.stringify(response.body)).toBe(200);
    const sid = response.body.sessionId;
    expect(response.body.status).toBe("open");

    const view = await action(req.actionId);
    expect(view).toMatchObject({
      type: "webauthn-sign",
      status: "completed",
      userVerification: "required",
    });
    expect(view.context).toMatchObject({ source: "endpoint-auth", trigger: { kind: "ui" } });

    await ws.attach(sid);
    await waitForPrompt(ws, sid);
    await run(ws, sid, "echo USER=$(whoami)", new RegExp(`USER=${SSHD_USER.passkey}`));
    await sc.api.delete(`/api/sessions/${sid}`);

    // sshd's VERBOSE log is the proof: the SK algorithm, for the passkey user.
    const log = await logsSince(target, since);
    expect(log).toMatch(
      new RegExp(`Accepted publickey for ${SSHD_USER.passkey} from [^\\n]* ECDSA-SK SHA256:`),
    );

    const row = await signing(req.actionId);
    expect(row).toMatchObject({
      type: "webauthn-sign",
      source: "endpoint-auth",
      outcome: "approved",
      credentialId: sc.identity.credentialId,
      userVerification: "required",
    });
    expect(row.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("rejects an assertion without the UV flag on a userVerification=required endpoint, then accepts a proper one", async () => {
    const pending = sc.api.post<{ sessionId: string; status: string; error?: string }>(
      "/api/sessions",
      { endpointId },
    );
    const req = await ws.next<SignRequestFrame>("sign:request", { timeoutMs: 20_000 });
    expect(req.actionType).toBe("webauthn-sign");

    const noUv = await approveSignRequest(sc.api, req, sc.identity, { uv: false });
    expect(noUv.status).toBe(400);
    expect(noUv.body.error).toMatch(/user verification required/i);
    expect((await action(req.actionId)).status).toBe("pending");

    const ok = await approveSignRequest(sc.api, req, sc.identity);
    expect(ok.status).toBe(200);
    const response = await pending;
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    await sc.api.delete(`/api/sessions/${response.body.sessionId}`);

    // A second resolve on the now-completed action is refused.
    const again = await approveSignRequest(sc.api, req, sc.identity);
    expect(again.status).toBe(409);
  });

  it("denying the request fails the SSH login without sshd ever accepting a key", async () => {
    const since = rec.mark();
    const { response, approvals } = await openSession({
      api: sc.api,
      ws,
      identity: sc.identity,
      endpointId,
      decide: () => "deny",
    });
    expect(approvals).toHaveLength(1);
    expect(approvals[0]!.body).toEqual({ status: "denied" });
    expect(response.status).toBe(400);
    expect(response.body.error).toMatch(/All configured authentication methods failed/);
    expect((await action(approvals[0]!.request.actionId)).status).toBe("denied");
    expect((await signing(approvals[0]!.request.actionId)).outcome).toBe("denied");

    const log = await logsSince(target, since);
    expect(log).toMatch(new RegExp(SSHD_USER.passkey));
    expect(log).not.toMatch(/Accepted publickey/);
  });

  it("expires an unanswered request after the 60 s TTL — before sshd's LoginGraceTime", async () => {
    const since = rec.mark();
    const started = Date.now();
    const pending = sc.api.post<{ error?: string }>("/api/sessions", { endpointId });
    const req = await ws.next<SignRequestFrame>("sign:request", { timeoutMs: 20_000 });

    const expired = await waitFor(
      async () => {
        const v = await action(req.actionId);
        return v.status === "expired" ? v : null;
      },
      { timeoutMs: 90_000, intervalMs: 1000, what: "action to expire" },
    );
    expect(expired.status).toBe("expired");
    const elapsed = Date.now() - started;
    // 60 s TTL + up to one 10 s sweep.
    expect(elapsed).toBeGreaterThanOrEqual(60_000);
    expect(elapsed).toBeLessThan(120_000);

    const response = await pending;
    expect(response.status).toBe(400);
    expect(response.body.error).toMatch(/All configured authentication methods failed/);
    expect((await signing(req.actionId)).outcome).toBe("expired");

    // The ordering only a real sshd can show: ShellWatch gave up first.
    const log = await logsSince(target, since);
    expect(log).toMatch(new RegExp(SSHD_USER.passkey));
    expect(log).not.toMatch(/Timeout before authentication/);
    expect(log).not.toMatch(/Accepted publickey/);
  });
});
