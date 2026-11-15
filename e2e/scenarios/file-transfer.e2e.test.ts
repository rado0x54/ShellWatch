// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * MCP file tools against a real OpenSSH sftp-server (#263). The in-process Go
 * suite covers the state machine against pkg/sftp's server; what only a real
 * sshd can prove is the OpenSSH-specific part: that `internal-sftp` advertises
 * the posix-rename/hardlink extensions the link upload insists on, that the
 * hardlink commit refuses an existing destination and posix-rename replaces
 * one atomically, and that modes and inodes on a real filesystem end up as the
 * contract says. Remote state is asserted from inside the container, not
 * through ShellWatch.
 */
import { createHash, randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SSHD_USER, sshdTargets, type SshdTarget } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import {
  connectMcp,
  connectWs,
  withApprovals,
  type WsClient,
  type WsFrame,
} from "../harness/clients.js";
import { loginThirdPartyClient } from "../harness/oauth.js";
import { recordScenario } from "../harness/out.js";
import { exec } from "../harness/sshd.js";
import { waitFor } from "../harness/util.js";
import type { TestMcpClient } from "../lib/mcp-client.js";

const HOME = `/home/${SSHD_USER.fileKey}`;
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

interface FileFrame extends WsFrame {
  type: "terminal:file";
  sessionId: string;
  transferId: string;
  tier: string;
  direction: string;
  path: string;
  status: string;
  bytes: number;
}

interface TransferStatus {
  transferId: string;
  status: string;
  bytes: number;
  sha256?: string;
  error?: string;
  commitOutcome?: string;
  cleanup?: string;
  stagingPath?: string;
  truncated?: boolean;
}

describe.each(sshdTargets())("MCP file transfer (real sshd-%s)", (target: SshdTarget) => {
  let sc: Scenario;
  let ws: WsClient;
  let mcp: TestMcpClient;
  let sessionId: string;
  const dir = `${HOME}/xfer-${target}`;
  const rec = recordScenario(`file-transfer-${target}`, () => sc?.server);

  const parse = <T = Record<string, unknown>>(r: { content: string; isError?: boolean }): T => {
    expect(r.isError, r.content).toBeFalsy();
    return JSON.parse(r.content) as T;
  };
  /** Run a shell command as root inside the sshd container. */
  const remote = (script: string) => exec(target, script).trim();
  const status = async (transferId: string) =>
    parse<TransferStatus>(
      await mcp.callTool("shellwatch_transfer_file", { action: "status", transferId }),
    );
  /** Poll status until the transfer is finished AND its cleanup settled. */
  const settled = (transferId: string) =>
    waitFor(
      async () => {
        const s = await status(transferId);
        const finished = !["pending", "active"].includes(s.status);
        const cleaned = s.status === "pending" || s.cleanup !== undefined || !s.stagingPath;
        return finished && cleaned ? s : null;
      },
      { what: `transfer ${transferId} to settle` },
    );
  const stagingLeftovers = () => remote(`ls -A ${dir} | grep '\\.tmp$' || true`);

  beforeAll(async () => {
    sc = await bootScenario({ scenario: `file-transfer-${target}`, targets: [target] });
    ws = await connectWs(sc.uiToken);
    const endpointId = await sc.createEndpoint({
      label: `E2E files ${target}`,
      target,
      username: SSHD_USER.fileKey,
      agentForward: false,
    });
    const login = await loginThirdPartyClient({
      clientName: "E2E File Client",
      scope: "mcp",
      identity: sc.identity,
    });
    mcp = await connectMcp(login.tokens.access_token);
    rec.note(`mcp client ${login.clientId}`);

    remote(`rm -rf ${dir} && mkdir -p ${dir} && chown ${SSHD_USER.fileKey}: ${dir}`);

    const { result } = await withApprovals(ws, sc.api, null, () =>
      mcp.callTool("shellwatch_create_session", { endpointId, reason: "e2e: file tools" }),
    );
    sessionId = parse<{ sessionId: string }>(result).sessionId;
    // Attach as the watching human: terminal:file frames go to attached tabs.
    await ws.attach(sessionId);
  });

  afterAll(async () => {
    await mcp?.close();
    ws?.close();
    await sc?.stop();
  });

  it("writes, reads and lists a small config inline; overwrite keeps inode and mode", async () => {
    const file = `${dir}/app.conf`;
    const content = "listen = 8080\n".repeat(700); // ~10 KB

    const written = parse<{ transferId: string; bytes: number; sha256: string }>(
      await mcp.callTool("shellwatch_write_file", {
        sessionId,
        path: file,
        content,
        mode: "0640",
      }),
    );
    expect(written).toMatchObject({ bytes: content.length, sha256: sha256(content) });
    // Asserted on the host: content, mode, and that the login user owns it.
    expect(remote(`sha256sum ${file} | cut -d' ' -f1`)).toBe(sha256(content));
    expect(remote(`stat -c '%a %U' ${file}`)).toBe(`640 ${SSHD_USER.fileKey}`);

    // The human watching the session saw it, with the same transferId.
    const frame = await ws.next<FileFrame>("terminal:file", {
      pred: (f) => f.transferId === written.transferId,
    });
    expect(frame).toMatchObject({
      sessionId,
      tier: "inline",
      direction: "upload",
      path: file,
      status: "completed",
      bytes: content.length,
    });

    const read = parse<{ content: string; sha256: string; modeOctal: string; size: number }>(
      await mcp.callTool("shellwatch_read_file", { sessionId, path: file }),
    );
    expect(read).toMatchObject({
      content,
      sha256: sha256(content),
      modeOctal: "0640",
      size: content.length,
    });

    // Exclusive create refuses an existing file…
    const clobber = await mcp.callTool("shellwatch_write_file", {
      sessionId,
      path: file,
      content: "x",
    });
    expect(clobber.isError).toBe(true);
    expect(clobber.content).toContain("already exists");
    // …and overwrite truncates in place: same inode, same mode.
    const inode = remote(`stat -c %i ${file}`);
    parse(
      await mcp.callTool("shellwatch_write_file", {
        sessionId,
        path: file,
        content: "listen = 9090\n",
        overwrite: true,
      }),
    );
    expect(remote(`stat -c '%i %a' ${file}`)).toBe(`${inode} 640`);
    expect(remote(`cat ${file}`)).toBe("listen = 9090");

    const listing = parse<{ entries: { name: string; type: string; modeOctal: string }[] }>(
      await mcp.callTool("shellwatch_list_dir", { sessionId, path: dir }),
    );
    expect(listing.entries).toContainEqual(
      expect.objectContaining({ name: "app.conf", type: "file", modeOctal: "0640" }),
    );

    // The file tools do not follow the shell: relative paths are refused.
    const relative = await mcp.callTool("shellwatch_read_file", { sessionId, path: "app.conf" });
    expect(relative.isError).toBe(true);
    expect(relative.content).toContain("path must be absolute");

    // Writing where the login user may not is the SFTP permission error.
    const denied = await mcp.callTool("shellwatch_write_file", {
      sessionId,
      path: "/etc/shellwatch-e2e-denied",
      content: "x",
    });
    expect(denied.isError).toBe(true);
    expect(remote("test -e /etc/shellwatch-e2e-denied && echo yes || echo no")).toBe("no");
  });

  it("uploads a binary through a single-use link: staged privately, committed by hardlink, cleaned up", async () => {
    const dest = `${dir}/backup.bin`;
    const payload = randomBytes(8 * 1024 * 1024);
    const created = parse<{
      transferId: string;
      url: string;
      method: string;
      command: string;
      maxBytes: number;
    }>(
      await mcp.callTool("shellwatch_transfer_file", {
        action: "create",
        sessionId,
        direction: "upload",
        path: dest,
        sha256: sha256(payload),
      }),
    );
    expect(created.method).toBe("PUT");
    expect(created.url.startsWith(`${sc.server.url}/api/transfers/`)).toBe(true);
    expect(created.command).toContain(`curl -fsS -T './backup.bin' '${created.url}'`);
    expect((await status(created.transferId)).status).toBe("pending");

    // What `curl -T` does: a raw-body PUT with no bearer token.
    const put = await fetch(created.url, { method: "PUT", body: payload });
    expect(put.status).toBe(200);
    expect(put.headers.get("cache-control")).toBe("no-store");
    expect(await put.json()).toMatchObject({ status: "completed", sha256: sha256(payload) });

    const done = await settled(created.transferId);
    expect(done).toMatchObject({
      status: "completed",
      bytes: payload.length,
      sha256: sha256(payload),
      commitOutcome: "ok",
      cleanup: "ok",
    });
    expect(done.stagingPath).toBeUndefined();
    // On the host: the bytes, the default mode, and no staging directory left.
    expect(remote(`sha256sum ${dest} | cut -d' ' -f1`)).toBe(sha256(payload));
    expect(remote(`stat -c '%a %U' ${dest}`)).toBe(`644 ${SSHD_USER.fileKey}`);
    expect(stagingLeftovers()).toBe("");

    // Single use: the same URL is now the uniform 404.
    const again = await fetch(created.url, { method: "PUT", body: payload });
    expect(again.status).toBe(404);

    // The watcher saw the link being issued and the transfer completing.
    const frames = ws.frames.filter(
      (f): f is FileFrame => f.type === "terminal:file" && f.transferId === created.transferId,
    );
    expect(frames[0]).toMatchObject({ tier: "link", direction: "upload", status: "pending" });
    expect(frames.some((f) => f.status === "completed")).toBe(true);

    // And it is in the audit log, attributed to the session.
    const audit = await sc.api.get<{ rows: Record<string, unknown>[] }>(
      `/api/audit/file-transfers?sessionId=${sessionId}&tier=link`,
    );
    expect(audit.body.rows.find((r) => r.transferId === created.transferId)).toMatchObject({
      status: "completed",
      path: dest,
      bytes: payload.length,
      sha256: sha256(payload),
      commitOutcome: "ok",
      cleanup: "ok",
    });
  });

  it("no-clobber fails on an existing destination; overwrite replaces it atomically", async () => {
    const dest = `${dir}/release.txt`;
    remote(`printf original > ${dest} && chown ${SSHD_USER.fileKey}: ${dest} && chmod 600 ${dest}`);
    const link = async (overwrite: boolean) =>
      parse<{ transferId: string; url: string }>(
        await mcp.callTool("shellwatch_transfer_file", {
          action: "create",
          sessionId,
          direction: "upload",
          path: dest,
          overwrite,
        }),
      );

    const refused = await link(false);
    const res = await fetch(refused.url, { method: "PUT", body: "intruder" });
    expect(res.status).toBe(409);
    expect((await settled(refused.transferId)).status).toBe("failed");
    expect(remote(`cat ${dest}`)).toBe("original");

    const replaced = await link(true);
    const ok = await fetch(replaced.url, { method: "PUT", body: "replacement" });
    expect(ok.status).toBe(200);
    expect(await settled(replaced.transferId)).toMatchObject({
      status: "completed",
      commitOutcome: "ok",
      cleanup: "ok",
    });
    expect(remote(`cat ${dest}`)).toBe("replacement");
    // The existing file's permission bits were carried over to the new inode.
    expect(remote(`stat -c %a ${dest}`)).toBe("600");
    expect(stagingLeftovers()).toBe("");

    // A symlink destination is refused before a link is even minted.
    remote(`ln -s ${dest} ${dir}/release.link`);
    const viaLink = await mcp.callTool("shellwatch_transfer_file", {
      action: "create",
      sessionId,
      direction: "upload",
      path: `${dir}/release.link`,
      overwrite: true,
    });
    expect(viaLink.isError).toBe(true);
    expect(viaLink.content).toContain("destination is a symlink");
  });

  it("downloads a file byte-identically through a link", async () => {
    const src = `${dir}/dump.bin`;
    remote(`head -c 6291456 /dev/urandom > ${src} && chown ${SSHD_USER.fileKey}: ${src}`);
    const expected = remote(`sha256sum ${src} | cut -d' ' -f1`);

    const created = parse<{ transferId: string; url: string; method: string; command: string }>(
      await mcp.callTool("shellwatch_transfer_file", {
        action: "create",
        sessionId,
        direction: "download",
        path: src,
      }),
    );
    expect(created.method).toBe("GET");
    expect(created.command).toContain(`curl -fsS -o './dump.bin' '${created.url}'`);

    const res = await fetch(created.url);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-length")).toBe("6291456");
    const body = Buffer.from(await res.arrayBuffer());
    expect(sha256(body)).toBe(expected);

    expect(await settled(created.transferId)).toMatchObject({
      status: "completed",
      bytes: 6291456,
      sha256: expected,
      truncated: false,
    });
  });

  it("cancels on request and invalidates unused links when the session closes", async () => {
    const mint = async (name: string) =>
      parse<{ transferId: string; url: string }>(
        await mcp.callTool("shellwatch_transfer_file", {
          action: "create",
          sessionId,
          direction: "upload",
          path: `${dir}/${name}`,
        }),
      );

    const cancelled = await mint("cancelled.bin");
    expect(
      parse<TransferStatus>(
        await mcp.callTool("shellwatch_transfer_file", {
          action: "cancel",
          transferId: cancelled.transferId,
        }),
      ).status,
    ).toBe("cancelled");
    expect((await fetch(cancelled.url, { method: "PUT", body: "late" })).status).toBe(404);

    const orphan = await mint("orphan.bin");
    parse(await mcp.callTool("shellwatch_close_session", { sessionId }));
    expect((await status(orphan.transferId)).status).toBe("cancelled");
    expect((await fetch(orphan.url, { method: "PUT", body: "late" })).status).toBe(404);
    expect(remote(`ls ${dir}`)).not.toMatch(/cancelled\.bin|orphan\.bin/);
  });
});
