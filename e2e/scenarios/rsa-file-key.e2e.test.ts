// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * RSA file-key endpoint auth — regression for the plain-ssh.Signer downgrade:
 * the approval-gated signer must preserve x/crypto's AlgorithmSigner
 * capability so the client offers rsa-sha2-256/512. Wrapped as a plain
 * Signer it falls back to ssh-rsa/SHA-1, which OpenSSH >= 8.8 rejects by
 * default — auth fails even after the human approves. The other scenarios
 * all use ed25519 (one algorithm), which can never catch this.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SSHD_USER, sshdTargets, type SshdTarget } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import { connectWs, openSession, run, waitForPrompt, type WsClient } from "../harness/clients.js";
import { recordScenario } from "../harness/out.js";
import { logsSince, sshdVersion } from "../harness/sshd.js";

describe.each(sshdTargets())("RSA file key on sshd-%s", (target: SshdTarget) => {
  const scenarioName = `rsa-file-key-${target}`;
  let sc: Scenario;
  let ws: WsClient;
  let endpointId: string;
  const rec = recordScenario(scenarioName, () => sc?.server);

  beforeAll(async () => {
    sc = await bootScenario({ scenario: scenarioName, targets: [target], fileKeyType: "rsa" });
    rec.note(`target ${target}: ${sshdVersion(target)}`);
    ws = await connectWs(sc.uiToken);
    endpointId = await sc.createEndpoint({
      label: `E2E RSA ${target}`,
      target,
      username: SSHD_USER.fileKey,
      agentForward: false,
    });
  });

  afterAll(async () => {
    ws?.close();
    await sc?.stop();
  });

  it("authenticates with rsa-sha2 after a key approval (no ssh-rsa/SHA-1 downgrade)", async () => {
    const since = rec.mark();
    const { response, approvals } = await openSession({
      api: sc.api,
      ws,
      identity: null,
      endpointId,
    });

    expect(approvals).toHaveLength(1);
    expect(approvals[0]!.status).toBe(200);
    expect(approvals[0]!.request).toMatchObject({
      actionType: "key-approve",
      keyFingerprint: sc.server.fileKey!.fingerprint,
    });
    expect(response.status, JSON.stringify(response.body)).toBe(200);
    const sid = response.body.sessionId;

    try {
      // A real shell round-trip proves the signature was accepted end to end.
      await ws.attach(sid);
      await waitForPrompt(ws, sid);
      const out = await run(ws, sid, "echo rsa-$((20 + 5))", "rsa-25");
      expect(out).toContain("rsa-25");

      // sshd accepted the RSA key — with the default PubkeyAcceptedAlgorithms
      // (no ssh-rsa) that is only possible via an rsa-sha2 signature.
      const log = await logsSince(target, since);
      expect(log).toMatch(
        new RegExp(`Accepted publickey for ${SSHD_USER.fileKey} from [^\\n]* RSA SHA256:`),
      );
    } finally {
      await sc.api.delete(`/api/sessions/${sid}`);
    }
  });
});
