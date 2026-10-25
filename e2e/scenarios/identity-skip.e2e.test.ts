// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Skip-identity semantics against a real sshd (#91, #244). When the human
 * denies a signature, the SSH client advances to its next identity instead of
 * aborting, and no signed attempt for the denied key reaches sshd: endpoint
 * auth offers one publickey method per key and drops the denied one; forwarded
 * and proxied requests answer SSH_AGENT_FAILURE, on which OpenSSH skips the
 * key. The only way to prove that is a user with TWO authorized keys: deny the
 * first (file key), approve the second (passkey), and the login must succeed —
 * on all three sign paths.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { modernEnabled, SSHD, SSHD_USER } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import {
  connectWs,
  openSession,
  run,
  waitForPrompt,
  withApprovals,
  type SignRequestFrame,
  type WsClient,
} from "../harness/clients.js";
import {
  hostSshSupportsWebauthnSk,
  runSsh,
  startAgentDaemon,
  type AgentDaemon,
} from "../harness/agent.js";
import { loginThirdPartyClient } from "../harness/oauth.js";
import { recordScenario } from "../harness/out.js";
import { installAuthorizedKeys, logsSince } from "../harness/sshd.js";

const target = "modern" as const;
const sshd = SSHD[target];
/** The user that accepts BOTH keys in this scenario. */
const BOTH = SSHD_USER.passkey;
const HOP_SSH =
  "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes";

/** Deny the file-key approval, approve the passkey. */
const denyFileKeyApprovePasskey = (req: SignRequestFrame) =>
  req.actionType === "key-approve" ? "deny" : "approve";

interface SigningRow {
  type: string;
  source: string;
  outcome: string | null;
}

describe.skipIf(!modernEnabled())(
  "skip-identity: deny the first matching key, succeed with the second",
  () => {
    let sc: Scenario;
    let ws: WsClient;
    let daemon: AgentDaemon | undefined;
    const rec = recordScenario("identity-skip", () => sc?.server);

    beforeAll(async () => {
      sc = await bootScenario({ scenario: "identity-skip", targets: [target] });
      // Both the ed25519 file key and the passkey are valid for this user, so
      // sshd accepts the file key's probe and the agent is asked to sign with it
      // first (file keys are offered before passkeys).
      installAuthorizedKeys(target, BOTH, [
        sc.server.fileKey!.publicKeyLine,
        sc.identity.openSshLine,
      ]);
      ws = await connectWs(sc.uiToken);
    });

    afterAll(async () => {
      await daemon?.stop();
      ws?.close();
      await sc?.stop();
    });

    const signing = async (id: string) =>
      (await sc.api.get<SigningRow>(`/api/audit/signings/${id}`)).body;

    async function expectDenyThenApprove(
      approvals: { request: SignRequestFrame; status: number; body: Record<string, unknown> }[],
      source: SignRequestFrame["source"],
    ) {
      expect(approvals.map((a) => a.request.actionType)).toEqual(["key-approve", "webauthn-sign"]);
      expect(approvals.every((a) => a.request.source === source)).toBe(true);
      expect(approvals[0]!.body).toEqual({ status: "denied" });
      expect(approvals[1]!.status, JSON.stringify(approvals[1]!.body)).toBe(200);
      expect((await signing(approvals[0]!.request.actionId)).outcome).toBe("denied");
      expect((await signing(approvals[1]!.request.actionId)).outcome).toBe("approved");
    }

    /**
     * sshd's view of the skip, identical on all three paths: it sees the file
     * key's probe (`Accepted key … found at authorized_keys:1` + `Postponed
     * publickey`) but never a signature for it — so no `Failed publickey` for
     * that key and no login with it — and then the passkey login. A denial
     * must not burn one of sshd's MaxAuthTries.
     */
    async function expectSshdSkippedThenAccepted(since: string) {
      const log = await logsSince(target, since);
      const fp = sc.server.fileKey!.fingerprint.replace(/[+/=]/g, "\\$&");
      expect(log).not.toMatch(new RegExp(`Accepted publickey for ${BOTH} [^\\n]* ED25519 `));
      expect(log).toMatch(
        new RegExp(`Accepted key ED25519 ${fp} found at /home/${BOTH}/.ssh/authorized_keys:1`),
      );
      expect(log).not.toMatch(
        new RegExp(`Failed publickey for ${BOTH} from [^\\n]* ED25519 ${fp}`),
      );
      expect(log).toMatch(
        new RegExp(`Accepted publickey for ${BOTH} from [^\\n]* ECDSA-SK SHA256:`),
      );
      return log;
    }

    it("endpoint-auth: the session opens with the passkey after the file-key approval is denied", async () => {
      const endpointId = await sc.createEndpoint({
        label: "E2E both keys",
        target,
        username: BOTH,
        agentForward: false,
      });
      const since = rec.mark();
      const { response, approvals } = await openSession({
        api: sc.api,
        ws,
        identity: sc.identity,
        endpointId,
        decide: denyFileKeyApprovePasskey,
      });
      expect(response.status, JSON.stringify(response.body)).toBe(200);
      const sid = response.body.sessionId;
      try {
        await expectDenyThenApprove(approvals, "endpoint-auth");
        await ws.attach(sid);
        await waitForPrompt(ws, sid);
        await run(ws, sid, "echo USER=$(whoami)", new RegExp(`USER=${BOTH}`));
        await expectSshdSkippedThenAccepted(since);
      } finally {
        await sc.api.delete(`/api/sessions/${sid}`);
      }
    });

    it("agent-forwarding: the second hop succeeds with the passkey after the forwarded file-key sign is denied", async () => {
      const endpointId = await sc.createEndpoint({
        label: "E2E forward both",
        target,
        username: SSHD_USER.fileKey,
        agentForward: true,
      });
      const { response } = await openSession({
        api: sc.api,
        ws,
        identity: sc.identity,
        endpointId,
      });
      expect(response.status, JSON.stringify(response.body)).toBe(200);
      const sid = response.body.sessionId;
      try {
        await ws.attach(sid);
        await waitForPrompt(ws, sid);
        const since = rec.mark();
        const { result: out, approvals } = await withApprovals(
          ws,
          sc.api,
          sc.identity,
          () =>
            run(
              ws,
              sid,
              `${HOP_SSH} ${BOTH}@localhost 'echo HOP=$((2+2))'; echo HOP-RC=$?`,
              /HOP-RC=\d+/,
              60_000,
            ),
          { decide: denyFileKeyApprovePasskey },
        );
        expect(out).toMatch(/HOP=4/);
        expect(out).toMatch(/HOP-RC=0/);
        await expectDenyThenApprove(approvals, "agent-forwarding");
        await expectSshdSkippedThenAccepted(since);
      } finally {
        await sc.api.delete(`/api/sessions/${sid}`);
      }
    });

    it.skipIf(!hostSshSupportsWebauthnSk())(
      "agent-proxy: the host ssh succeeds with the passkey after the proxied file-key sign is denied",
      async () => {
        const agent = await loginThirdPartyClient({
          clientName: "shellwatch-agent",
          scope: "agent",
          identity: sc.identity,
        });
        daemon = await startAgentDaemon({ token: agent.tokens.access_token });
        const since = rec.mark();
        const { result, approvals } = await withApprovals(
          ws,
          sc.api,
          sc.identity,
          () =>
            runSsh({
              socketPath: daemon!.socketPath,
              user: BOTH,
              host: sshd.host,
              port: sshd.port,
              command: "echo PROXY=$((3+3))",
            }),
          { decide: denyFileKeyApprovePasskey },
        );
        expect(result.code, result.stderr).toBe(0);
        expect(result.stdout).toContain("PROXY=6");
        await expectDenyThenApprove(approvals, "agent-proxy");
        await expectSshdSkippedThenAccepted(since);
      },
    );
  },
);
