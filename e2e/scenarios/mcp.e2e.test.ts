// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * MCP over the wire (#244): the official SDK client, authenticated with a
 * Hydra-issued `mcp` token obtained through mediated DCR + the real
 * authorization_code + PKCE flow, drives a real SSH session through the tool
 * surface. Plus cross-account isolation with a second, self-registered account.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SSHD_USER, sshdTargets, type SshdTarget } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import {
  Api,
  connectMcp,
  connectWs,
  rawMcpPing,
  withApprovals,
  type WsClient,
} from "../harness/clients.js";
import { createPasskeyIdentity } from "../harness/identity.js";
import { loginThirdPartyClient, loginWebUi, selfRegister } from "../harness/oauth.js";
import { recordScenario } from "../harness/out.js";
import { waitFor } from "../harness/util.js";
import type { TestMcpClient } from "../../src/test/helpers/mcp-client.js";

const target: SshdTarget = sshdTargets()[0]!;
const MCP_REASON = "e2e: verify the tool surface against a real sshd";

describe(`MCP (Hydra token, real sshd-${target})`, () => {
  let sc: Scenario;
  let ws: WsClient;
  let mcpToken: string;
  let endpointId: string;
  const rec = recordScenario("mcp", () => sc?.server);

  beforeAll(async () => {
    sc = await bootScenario({ scenario: "mcp", targets: [target], selfRegistrationEnabled: true });
    ws = await connectWs(sc.uiToken);
    endpointId = await sc.createEndpoint({
      label: "E2E mcp",
      target,
      username: SSHD_USER.fileKey,
      agentForward: false,
      description: "e2e target for the MCP scenario",
    });
    const mcp = await loginThirdPartyClient({
      clientName: "E2E MCP Client",
      scope: "mcp",
      identity: sc.identity,
    });
    expect(mcp.tokens.scope?.split(" ")).toContain("mcp");
    expect(mcp.tokens.refresh_token).toBeTruthy();
    mcpToken = mcp.tokens.access_token;
    rec.note(`mcp client ${mcp.clientId}: ${mcp.trace.steps.join(" | ")}`);
  });

  afterAll(async () => {
    ws?.close();
    await sc?.stop();
  });

  const parse = (r: { content: string }) => JSON.parse(r.content) as Record<string, unknown>;

  it("runs the full tool lifecycle: endpoints → session → send_keys → read_output → notification → close, audited as mcp", async () => {
    const mcp: TestMcpClient = await connectMcp(mcpToken);
    try {
      const list = parse(await mcp.callTool("shellwatch_manage_endpoints", { action: "list" })) as {
        endpoints: {
          id: string;
          label: string;
          host: string;
          port: number;
          username: string;
          description: string | null;
        }[];
      };
      const ep = list.endpoints.find((e) => e.id === endpointId);
      expect(ep).toMatchObject({
        label: "E2E mcp",
        username: SSHD_USER.fileKey,
        description: "e2e target for the MCP scenario",
      });

      const read = parse(
        await mcp.callTool("shellwatch_manage_endpoints", { action: "read", id: endpointId }),
      );
      expect(read).toMatchObject({ id: endpointId, label: "E2E mcp" });

      // MCP create: caller-supplied id (documented divergence from REST).
      const created = parse(
        await mcp.callTool("shellwatch_manage_endpoints", {
          action: "create",
          id: "e2e-mcp-created",
          data: { label: "Created by MCP", host: "198.51.100.7", port: 22, username: "nobody" },
        }),
      );
      expect(created).toEqual({ status: "created", id: "e2e-mcp-created" });
      const viaRest = await sc.api.get<{ endpoints: { id: string }[] }>("/api/endpoints");
      expect(viaRest.body.endpoints.map((e) => e.id)).toContain("e2e-mcp-created");

      // Session creation needs the human to approve the file-key signature.
      const { result: createRes, approvals } = await withApprovals(ws, sc.api, null, () =>
        mcp.callTool("shellwatch_create_session", { endpointId, reason: MCP_REASON }),
      );
      expect(createRes.isError, createRes.content).toBeFalsy();
      const session = parse(createRes) as { sessionId: string; endpointId: string; status: string };
      expect(session).toMatchObject({ endpointId, status: "open" });
      expect(approvals).toHaveLength(1);
      expect(approvals[0]!.request).toMatchObject({
        actionType: "key-approve",
        source: "endpoint-auth",
      });

      const sessions = parse(await mcp.callTool("shellwatch_list_sessions")) as {
        sessions: { sessionId: string }[];
      };
      expect(sessions.sessions.map((s) => s.sessionId)).toContain(session.sessionId);

      const sent = parse(
        await mcp.callTool("shellwatch_send_keys", {
          sessionId: session.sessionId,
          keys: ["text:echo MCP=$((5+5))", "enter"],
        }),
      );
      expect(sent).toEqual({ status: "sent", keys: ["text:echo MCP=$((5+5))", "enter"] });
      const notif = await mcp.waitForNotification(
        "notifications/shellwatch/output_available",
        10_000,
      );
      expect(notif.params).toMatchObject({ sessionId: session.sessionId });

      const out1 = await waitFor(
        async () => {
          const r = parse(
            await mcp.callTool("shellwatch_read_output", { sessionId: session.sessionId }),
          ) as {
            data: string;
            offset: number;
            hasMore: boolean;
          };
          return /MCP=10/.test(r.data) ? r : null;
        },
        { what: "MCP=10 in read_output" },
      );
      expect(out1.offset).toBeGreaterThan(0);

      // Incremental read from the previous offset excludes what we already saw.
      await mcp.callTool("shellwatch_send_keys", {
        sessionId: session.sessionId,
        keys: ["text:echo NEXT=$((6+6))", "enter"],
      });
      const out2 = await waitFor(
        async () => {
          const r = parse(
            await mcp.callTool("shellwatch_read_output", {
              sessionId: session.sessionId,
              afterOffset: out1.offset,
            }),
          ) as {
            data: string;
            offset: number;
          };
          return /NEXT=12/.test(r.data) ? r : null;
        },
        { what: "NEXT=12 in incremental read_output" },
      );
      expect(out2.data).not.toContain("MCP=10");
      expect(out2.offset).toBeGreaterThan(out1.offset);

      // The web UI (same account) sees the MCP session as an observer.
      await waitFor(() =>
        ws.sessions().some((s) => s.sessionId === session.sessionId && s.source === "mcp"),
      );

      const closed = parse(
        await mcp.callTool("shellwatch_close_session", { sessionId: session.sessionId }),
      );
      expect(closed).toEqual({ status: "closed" });
      const after = parse(await mcp.callTool("shellwatch_list_sessions")) as {
        sessions: unknown[];
      };
      expect(after.sessions).toHaveLength(0);

      // Audit: the session and the signing request carry the MCP trigger metadata.
      const audit = await waitFor(async () => {
        const res = await sc.api.get<{ rows: Record<string, unknown>[] }>("/api/audit/sessions");
        const row = res.body.rows.find((r) => r.sessionId === session.sessionId);
        return row?.status === "closed" ? row : null;
      });
      expect(audit).toMatchObject({
        source: "mcp",
        closeReason: "client.mcp",
        mcpReason: MCP_REASON,
        mcpClientName: "test-client",
        mcpClientVersion: "1.0.0",
      });
      const signing = await sc.api.get<Record<string, unknown>>(
        `/api/audit/signings/${approvals[0]!.request.actionId}`,
      );
      expect(signing.body).toMatchObject({
        source: "endpoint-auth",
        outcome: "approved",
        mcpReason: MCP_REASON,
        mcpClientName: "test-client",
      });

      const del = parse(
        await mcp.callTool("shellwatch_manage_endpoints", {
          action: "delete",
          id: "e2e-mcp-created",
        }),
      );
      expect(del).toEqual({ status: "deleted", id: "e2e-mcp-created" });
    } finally {
      await mcp.close();
    }
  });

  it("enforces scopes per surface", async () => {
    expect(await rawMcpPing(null)).toBe(401);
    expect(await rawMcpPing(sc.uiToken)).toBe(403); // ui token lacks mcp
    const asMcp = new Api(mcpToken);
    expect((await asMcp.get("/api/sessions")).status).toBe(403); // mcp token lacks ui
    const anon = await fetch(`${sc.server.url}/mcp`, { method: "POST" });
    expect(anon.headers.get("www-authenticate")).toContain(
      `resource_metadata="${sc.server.url}/.well-known/oauth-protected-resource/mcp"`,
    );
  });

  it("isolates accounts: a second account sees none of the first account's endpoints or sessions", async () => {
    const other = createPasskeyIdentity("E2E second account");
    const { accountId: otherId } = await selfRegister(other, "Second Account");
    expect(otherId).not.toBe(sc.accountId);
    const otherUi = new Api((await loginWebUi(other)).tokens.access_token);
    const me = await otherUi.get<{ id: string; isAdmin: boolean; name: string }>("/api/auth/me");
    expect(me.body).toMatchObject({ id: otherId, isAdmin: false, name: "Second Account" });
    const otherMcpToken = (
      await loginThirdPartyClient({ clientName: "Other MCP", scope: "mcp", identity: other })
    ).tokens.access_token;

    // First account opens a session.
    const { response } = await withApprovals(ws, sc.api, null, () =>
      sc.api.post<{ sessionId: string }>("/api/sessions", { endpointId }),
    ).then((r) => ({ response: r.result }));
    expect(response.status).toBe(200);
    const sid = response.body.sessionId;
    try {
      // REST as the other account.
      expect(
        (await otherUi.get<{ endpoints: unknown[] }>("/api/endpoints")).body.endpoints,
      ).toHaveLength(0);
      expect(
        (await otherUi.get<{ sessions: unknown[] }>("/api/sessions")).body.sessions,
      ).toHaveLength(0);
      expect((await otherUi.get(`/api/sessions/${sid}/tail`)).status).toBe(404);
      expect((await otherUi.delete(`/api/sessions/${sid}`)).status).toBe(404);
      expect((await otherUi.post("/api/sessions", { endpointId })).status).toBe(404);
      expect(
        (await otherUi.get<{ rows: unknown[] }>("/api/audit/sessions")).body.rows,
      ).toHaveLength(0);
      // Non-admin: no file keys listed.
      expect((await otherUi.get<{ keys: unknown[] }>("/api/keys")).body.keys).toHaveLength(0);

      // MCP as the other account.
      const otherMcp = await connectMcp(otherMcpToken);
      try {
        const list = parse(
          await otherMcp.callTool("shellwatch_manage_endpoints", { action: "list" }),
        ) as { endpoints: unknown[] };
        expect(list.endpoints).toHaveLength(0);
        const read = await otherMcp.callTool("shellwatch_manage_endpoints", {
          action: "read",
          id: endpointId,
        });
        expect(read.isError).toBe(true);
        const out = await otherMcp.callTool("shellwatch_read_output", { sessionId: sid });
        expect(out.isError).toBe(true);
        const create = await otherMcp.callTool("shellwatch_create_session", {
          endpointId,
          reason: "cross-account probe",
        });
        expect(create.isError).toBe(true);
      } finally {
        await otherMcp.close();
      }

      // The first account's WS never saw a session of the other account, and vice versa.
      const otherWs = await connectWs(otherUi.token!);
      try {
        await otherWs.next("sessions:changed");
        expect(otherWs.sessions()).toHaveLength(0);
      } finally {
        otherWs.close();
      }
    } finally {
      await sc.api.delete(`/api/sessions/${sid}`);
    }
  });
});
