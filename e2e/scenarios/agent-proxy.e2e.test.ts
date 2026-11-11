// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * The system-ssh path (#22/#36) against a real sshd (#244): the Go
 * `shellwatch-agent` holds an `agent`-scoped Hydra token obtained through the
 * real DCR + PKCE flow, exposes SSH_AUTH_SOCK on the host, and the host's `ssh`
 * authenticates to sshd through ShellWatch's human approval — file key on any
 * OpenSSH client, passkey when the host client is >= 10.3.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { modernEnabled, SSHD, SSHD_USER } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import { connectWs, withApprovals, type WsClient } from "../harness/clients.js";
import {
  hostSshSupportsWebauthnSk,
  hostSshVersion,
  runSsh,
  sshAddList,
  startAgentDaemon,
  startAgentLogin,
  type AgentDaemon,
} from "../harness/agent.js";
import { CookieJar, driveAuthorize, loginThirdPartyClient } from "../harness/oauth.js";
import { recordScenario } from "../harness/out.js";
import { logsSince } from "../harness/sshd.js";

const target = "modern" as const;
const sshd = SSHD[target];
// `shellwatch-agent login` writes to the OS keyring on macOS; the harness only
// redirects it to the file store on Linux (CI). Force with E2E_AGENT_LOGIN=1.
const loginFlowEnabled = process.platform === "linux" || process.env.E2E_AGENT_LOGIN === "1";

describe.skipIf(!modernEnabled())("agent proxy (system ssh) against sshd-modern", () => {
  let sc: Scenario;
  let ws: WsClient;
  let daemon: AgentDaemon;
  let agentClientId: string;
  const rec = recordScenario("agent-proxy", () => sc?.server);

  beforeAll(async () => {
    sc = await bootScenario({ scenario: "agent-proxy", targets: [target] });
    ws = await connectWs(sc.uiToken);
    rec.note(`host ssh: ${hostSshVersion().raw}`);
    const agent = await loginThirdPartyClient({
      clientName: "shellwatch-agent",
      scope: "agent",
      identity: sc.identity,
    });
    agentClientId = agent.clientId;
    expect(agent.tokens.scope?.split(" ")).toContain("agent");
    daemon = await startAgentDaemon({ token: agent.tokens.access_token });
  });

  afterAll(async () => {
    await daemon?.stop();
    ws?.close();
    await sc?.stop();
  });

  it("lists the server-held identities through the local agent socket", () => {
    const list = sshAddList(daemon.socketPath);
    expect(list.code, list.stderr).toBe(0);
    const fileKeyBlob = sc.server.fileKey!.publicKeyLine.split(" ")[1];
    expect(list.stdout).toContain(`ssh-ed25519 ${fileKeyBlob}`);
    if (hostSshSupportsWebauthnSk()) {
      // Canonical sk-ecdsa type, same blob — see agent-forwarding scenario.
      expect(list.stdout).toContain(sc.identity.skOpenSshLine);
    }
  });

  it("authenticates the host ssh with the file key after a key-approve on /sign", async () => {
    const since = rec.mark();
    const { result, approvals } = await withApprovals(ws, sc.api, null, () =>
      runSsh({
        socketPath: daemon.socketPath,
        user: SSHD_USER.fileKey,
        host: sshd.host,
        port: sshd.port,
        command: "echo PROXY=$((20+1))",
      }),
    );
    expect(result.code, result.stderr).toBe(0);
    expect(result.stdout).toContain("PROXY=21");
    expect(approvals.length).toBeGreaterThanOrEqual(1);
    const keyApproval = approvals.find((a) => a.request.actionType === "key-approve");
    expect(keyApproval?.request).toMatchObject({
      source: "agent-proxy",
      keyFingerprint: sc.server.fileKey!.fingerprint,
    });

    const row = (
      await sc.api.get<{
        source: string;
        outcome: string;
        clientOs: string | null;
        clientHostname: string | null;
        clientVersion: string | null;
        sourceIp: string | null;
      }>(`/api/audit/signings/${keyApproval!.request.actionId}`)
    ).body;
    expect(row).toMatchObject({
      source: "agent-proxy",
      outcome: "approved",
      sourceIp: "127.0.0.1",
    });
    // Self-reported client metadata from the agent's handshake headers.
    expect(row.clientOs).toMatch(/^(darwin|linux)\/(arm64|amd64)$/);
    expect(row.clientHostname).toBeTruthy();
    expect(row.clientVersion).toBeTruthy();

    const log = await logsSince(target, since);
    expect(log).toMatch(
      new RegExp(`Accepted publickey for ${SSHD_USER.fileKey} from [^\\n]* ED25519 `),
    );
  });

  it.skipIf(!hostSshSupportsWebauthnSk())(
    "authenticates the host ssh with the passkey (webauthn-sk) after a passkey approval",
    async () => {
      const since = rec.mark();
      const { result, approvals } = await withApprovals(ws, sc.api, sc.identity, () =>
        runSsh({
          socketPath: daemon.socketPath,
          user: SSHD_USER.passkey,
          host: sshd.host,
          port: sshd.port,
          command: "echo PROXY=$((30+3))",
        }),
      );
      expect(result.code, result.stderr).toBe(0);
      expect(result.stdout).toContain("PROXY=33");
      const passkeyApproval = approvals.find((a) => a.request.actionType === "webauthn-sign");
      expect(passkeyApproval?.request).toMatchObject({
        source: "agent-proxy",
        credentialId: sc.identity.credentialId,
      });
      const log = await logsSince(target, since);
      expect(log).toMatch(
        new RegExp(`Accepted publickey for ${SSHD_USER.passkey} from [^\\n]* ECDSA-SK SHA256:`),
      );
    },
  );

  it("denying the approval makes ssh fail with permission denied", async () => {
    const since = rec.mark();
    const { result, approvals } = await withApprovals(
      ws,
      sc.api,
      sc.identity,
      () =>
        runSsh({
          socketPath: daemon.socketPath,
          user: SSHD_USER.fileKey,
          host: sshd.host,
          port: sshd.port,
          command: "true",
        }),
      { decide: () => "deny" },
    );
    expect(result.code).toBe(255);
    expect(result.stderr).toMatch(/Permission denied/);
    expect(approvals.length).toBeGreaterThanOrEqual(1);
    expect(approvals.every((a) => a.body.status === "denied")).toBe(true);
    const log = await logsSince(target, since);
    expect(log).not.toMatch(/Accepted publickey/);
  });

  it("the agent's client is listed as an authorized client of the account", async () => {
    const res = await sc.api.get<{
      sessions: { clientId: string; clientName: string; scopes: string[]; current: boolean }[];
    }>("/api/auth/sessions");
    expect(res.status).toBe(200);
    const row = res.body.sessions.find((s) => s.clientId === agentClientId);
    expect(row).toMatchObject({ clientName: "shellwatch-agent", current: false });
    expect(row!.scopes).toContain("agent");
  });

  it.skipIf(!loginFlowEnabled)(
    "`shellwatch-agent login` completes the loopback flow headlessly and the daemon mints tokens from the stored refresh token",
    async () => {
      const login = await startAgentLogin();
      const redirectUri = new URL(login.authorizeUrl).searchParams.get("redirect_uri")!;
      expect(redirectUri).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/);
      const { finalUrl, trace } = await driveAuthorize(login.authorizeUrl, {
        identity: sc.identity,
        jar: new CookieJar(),
        redirectUriPrefix: redirectUri,
      });
      expect(trace.consent).toBe("approve");
      // Deliver the code to the agent's loopback listener, as the browser would.
      const cb = await fetch(finalUrl);
      expect(cb.status).toBe(200);
      const result = await login.result;
      expect(result.code, result.stdout).toBe(0);
      expect(result.stdout).toContain("OK: authorized");

      // Daemon with no --token: credentials come from the (file) credstore and
      // the access token is minted via the refresh_token grant.
      const d2 = await startAgentDaemon({ env: login.env });
      try {
        const { result: ssh } = await withApprovals(ws, sc.api, null, () =>
          runSsh({
            socketPath: d2.socketPath,
            user: SSHD_USER.fileKey,
            host: sshd.host,
            port: sshd.port,
            command: "echo LOGIN=$((7*6))",
          }),
        );
        expect(ssh.code, `${ssh.stderr}\n${d2.output()}`).toBe(0);
        expect(ssh.stdout).toContain("LOGIN=42");
      } finally {
        await d2.stop();
      }
    },
  );
});
