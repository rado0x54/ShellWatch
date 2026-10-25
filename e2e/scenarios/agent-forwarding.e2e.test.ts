// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * SSH agent forwarding against a real sshd (#244): with `agentForward: true`
 * the remote shell sees ShellWatch's agent (file key + passkey), and a second
 * hop from inside the container (`ssh passkey@localhost`) produces a
 * `webauthn-sign` request on the agent-forwarding channel that the human
 * approves — the forwarded sign path end to end, verified by sshd's log.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { modernEnabled, SSHD_USER } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import {
  connectWs,
  openSession,
  run,
  waitForPrompt,
  withApprovals,
  type WsClient,
} from "../harness/clients.js";
import { recordScenario } from "../harness/out.js";
import { logsSince } from "../harness/sshd.js";

const target = "modern" as const;
const HOP_SSH =
  "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes";

describe.skipIf(!modernEnabled())("agent forwarding against sshd-modern", () => {
  let sc: Scenario;
  let ws: WsClient;
  const rec = recordScenario("agent-forwarding", () => sc?.server);

  beforeAll(async () => {
    sc = await bootScenario({ scenario: "agent-forwarding", targets: [target] });
    ws = await connectWs(sc.uiToken);
  });

  afterAll(async () => {
    ws?.close();
    await sc?.stop();
  });

  it("exposes ShellWatch's keys to the remote shell and signs a second hop with the passkey", async () => {
    const endpointId = await sc.createEndpoint({
      label: "E2E forward on",
      target,
      username: SSHD_USER.fileKey,
      agentForward: true,
    });
    const { response } = await openSession({ api: sc.api, ws, identity: sc.identity, endpointId });
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    const sid = response.body.sessionId;
    try {
      await ws.attach(sid);
      await waitForPrompt(ws, sid);

      // The forwarded agent lists the file key and the passkey. OpenSSH prints
      // the passkey with the canonical sk-ecdsa key type (the webauthn- prefix
      // is a signature algorithm, not a key type) and the identical blob.
      const listing = await run(ws, sid, "ssh-add -L; echo LIST-RC=$?", /LIST-RC=\d/);
      expect(listing).toMatch(/LIST-RC=0/);
      expect(listing).toContain(sc.server.fileKey!.publicKeyLine.split(" ").slice(0, 2).join(" "));
      expect(listing).toContain(sc.identity.skOpenSshLine);

      // Second hop as the passkey-only user: sshd rejects the file-key probe
      // (not in authorized_keys), then the webauthn key is signed through the
      // forwarded channel → a sign request with source agent-forwarding.
      const since = rec.mark();
      const { result: out, approvals } = await withApprovals(ws, sc.api, sc.identity, () =>
        run(
          ws,
          sid,
          `${HOP_SSH} ${SSHD_USER.passkey}@localhost 'echo HOP=$((1+1))'; echo HOP-RC=$?`,
          /HOP-RC=\d+/,
          60_000,
        ),
      );
      expect(out).toMatch(/HOP=2/);
      expect(out).toMatch(/HOP-RC=0/);
      expect(approvals).toHaveLength(1);
      expect(approvals[0]!.status).toBe(200);
      expect(approvals[0]!.request).toMatchObject({
        actionType: "webauthn-sign",
        source: "agent-forwarding",
        credentialId: sc.identity.credentialId,
        endpointLabel: "E2E forward on",
      });

      const row = (
        await sc.api.get<{
          source: string;
          sessionId: string | null;
          outcome: string | null;
          type: string;
        }>(`/api/audit/signings/${approvals[0]!.request.actionId}`)
      ).body;
      expect(row).toMatchObject({
        type: "webauthn-sign",
        source: "agent-forwarding",
        sessionId: sid,
        outcome: "approved",
      });

      const log = await logsSince(target, since);
      expect(log).toMatch(
        new RegExp(
          `Accepted publickey for ${SSHD_USER.passkey} from 127\\.0\\.0\\.1 [^\\n]* ECDSA-SK SHA256:`,
        ),
      );
    } finally {
      await sc.api.delete(`/api/sessions/${sid}`);
    }
  });

  it("does not expose an agent when agentForward is off", async () => {
    const endpointId = await sc.createEndpoint({
      label: "E2E forward off",
      target,
      username: SSHD_USER.fileKey,
      agentForward: false,
    });
    const { response } = await openSession({ api: sc.api, ws, identity: sc.identity, endpointId });
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    const sid = response.body.sessionId;
    try {
      await ws.attach(sid);
      await waitForPrompt(ws, sid);
      const listing = await run(
        ws,
        sid,
        'echo "SOCK=[$SSH_AUTH_SOCK]"; ssh-add -L; echo LIST-RC=$?',
        /LIST-RC=\d/,
      );
      expect(listing).toMatch(/SOCK=\[\]/);
      expect(listing).not.toMatch(/LIST-RC=0/);
      expect(listing).not.toContain(sc.identity.skOpenSshLine);
    } finally {
      await sc.api.delete(`/api/sessions/${sid}`);
    }
  });
});
