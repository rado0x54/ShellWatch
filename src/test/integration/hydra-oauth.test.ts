// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Integration coverage for the Hydra OAuth surfaces (#217) — replaces the old
 * oauth-flow.test.ts that exercised the deleted shim. Hydra itself is faked
 * (see helpers/fake-hydra), so this runs in CI without a live Hydra:
 *
 *   - mediated DCR (/oauth/register) enforces the redirect-URI + scope policy,
 *   - the bearer gate validates tokens via introspection and rejects within the
 *     cache TTL once a token is revoked (instant-revocation property),
 *   - Settings → OAuth Clients mints/lists/deletes confidential clients.
 *
 * The end-to-end authorization-code + passkey login/consent path needs a real
 * Hydra and is covered by the manual verification steps in docs/deployment.md.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mintStepUpToken, STEPUP_ACTION } from "../../webauthn/stepup-store.js";
import {
  createTestLog,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

describe("Hydra OAuth surfaces", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let appServer: TestAppServer;

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
    appServer = await startTestApp(sshServer, log);
  });

  afterAll(async () => {
    await appServer?.close();
    await sshServer?.close();
  });

  describe("mediated DCR (/oauth/register)", () => {
    it("provisions a public client for an allowed loopback redirect", async () => {
      const res = await fetch(`${appServer.url}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "Test MCP",
          redirect_uris: ["http://127.0.0.1:9876/callback"],
          scope: "mcp",
        }),
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as { client_id: string; token_endpoint_auth_method: string };
      expect(body.client_id).toBeTruthy();
      expect(body.token_endpoint_auth_method).toBe("none");
      // The client was actually created in (fake) Hydra.
      expect(appServer.hydraAdmin.clients.has(body.client_id)).toBe(true);
    });

    it("rejects a redirect_uri outside the policy allowlist", async () => {
      const res = await fetch(`${appServer.url}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://evil.example.com/cb"], scope: "mcp" }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("invalid_redirect_uri");
    });

    it("rejects a scope outside the allowed set", async () => {
      const res = await fetch(`${appServer.url}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          redirect_uris: ["http://localhost:9876/callback"],
          scope: "root", // not in {mcp, agent}
        }),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("invalid_scope");
    });

    it("provisions an agent-scoped client (loopback agent-client onboarding)", async () => {
      const res = await fetch(`${appServer.url}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "shellwatch-agent",
          redirect_uris: ["http://127.0.0.1:51000/callback"],
          scope: "agent",
        }),
      });
      expect(res.status).toBe(201);
      const body = (await res.json()) as { client_id: string; scope: string };
      expect(body.client_id).toBeTruthy();
      // `offline` is always added so the client can obtain a refresh token.
      expect(body.scope).toContain("agent");
      expect(body.scope).toContain("offline");
    });
  });

  describe("bearer gate (introspection + revocation)", () => {
    it("rejects a request with no bearer token", async () => {
      const res = await fetch(`${appServer.url}/mcp`, { method: "POST" });
      expect(res.status).toBe(401);
    });

    it("accepts a valid mcp-scoped token, then 401s after revocation", async () => {
      // A valid token passes the gate (the MCP layer may then reject the body,
      // but the gate itself does not 401).
      const ok = await fetch(`${appServer.url}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${appServer.apiKey}`,
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      });
      expect(ok.status).not.toBe(401);

      // Revoke at (fake) Hydra → next introspection is inactive. The test
      // config sets introspectionCacheTtlMs: 0, so it takes effect immediately.
      appServer.hydraAdmin.revokeRegisteredToken(appServer.apiKey);

      const denied = await fetch(`${appServer.url}/mcp`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${appServer.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
      });
      expect(denied.status).toBe(401);

      // Restore for any later tests sharing this app.
      appServer.hydraAdmin.registerToken(appServer.apiKey, {
        sub: appServer.accountId,
        scope: "mcp",
        client_id: "test-mcp-client",
      });
    });
  });

  describe("auth session management (/api/auth/sessions, #219)", () => {
    const ui = () => ({ authorization: `Bearer ${appServer.uiToken}` });
    const stepUp = (action: (typeof STEPUP_ACTION)[keyof typeof STEPUP_ACTION]) => ({
      "x-shellwatch-stepup-token": mintStepUpToken({ accountId: appServer.accountId, action })
        .token,
    });

    it("lists consent sessions including the web UI client, flagged current", async () => {
      const spaId = appServer.config.hydra.spa.clientId;
      appServer.hydraAdmin.setConsentSessions(appServer.accountId, [
        {
          consent_request: { client: { client_id: spaId, client_name: "ShellWatch Web" } },
          grant_scope: ["ui", "offline"],
          handled_at: "2026-01-01T00:00:00Z",
        },
        {
          consent_request: {
            client: { client_id: "mcp-abc", client_name: "Claude MCP", created_at: "2026-01-30Z" },
          },
          grant_scope: ["mcp", "offline"],
          handled_at: "2026-02-01T00:00:00Z",
        },
      ]);
      const res = await fetch(`${appServer.url}/api/auth/sessions`, { headers: ui() });
      expect(res.status).toBe(200);
      const { sessions } = (await res.json()) as {
        sessions: { clientId: string; current: boolean; scopes: string[] }[];
      };
      expect(sessions).toHaveLength(2);
      // The first-party web UI client is included, flagged current, and sorted
      // first — even though the MCP grant was authorized more recently.
      expect(sessions[0]!.clientId).toBe(spaId);
      expect(sessions.find((s) => s.clientId === spaId)?.current).toBe(true);
      expect(sessions.find((s) => s.clientId === "mcp-abc")?.current).toBe(false);
    });

    it("rejects listing without a ui token", async () => {
      const res = await fetch(`${appServer.url}/api/auth/sessions`);
      expect(res.status).toBe(401);
    });

    it("revoking a single session requires a step-up token", async () => {
      const res = await fetch(`${appServer.url}/api/auth/sessions/mcp-abc`, {
        method: "DELETE",
        headers: ui(),
      });
      expect(res.status).toBe(401);
    });

    it("revokes a single client's consent with a step-up token", async () => {
      const before = appServer.hydraAdmin.revokedConsent.length;
      const res = await fetch(`${appServer.url}/api/auth/sessions/mcp-abc`, {
        method: "DELETE",
        headers: { ...ui(), ...stepUp(STEPUP_ACTION.revokeSession) },
      });
      expect(res.status).toBe(200);
      const recorded = appServer.hydraAdmin.revokedConsent.slice(before);
      expect(recorded).toContainEqual({ subject: appServer.accountId, clientId: "mcp-abc" });
    });

    it("revoke-all requires a step-up token", async () => {
      const res = await fetch(`${appServer.url}/api/auth/sessions/revoke-all`, {
        method: "POST",
        headers: ui(),
      });
      expect(res.status).toBe(401);
    });

    it("revoke-all clears consent + login sessions with a step-up token", async () => {
      const res = await fetch(`${appServer.url}/api/auth/sessions/revoke-all`, {
        method: "POST",
        headers: { ...ui(), ...stepUp(STEPUP_ACTION.revokeAllSessions) },
      });
      expect(res.status).toBe(200);
      // All-clients consent revoke (no clientId) + login-session revoke.
      expect(appServer.hydraAdmin.revokedConsent).toContainEqual({
        subject: appServer.accountId,
        clientId: undefined,
      });
      expect(appServer.hydraAdmin.revokedLogin).toContain(appServer.accountId);
    });

    it("a single-revoke step-up token can't be replayed against revoke-all", async () => {
      const res = await fetch(`${appServer.url}/api/auth/sessions/revoke-all`, {
        method: "POST",
        headers: { ...ui(), ...stepUp(STEPUP_ACTION.revokeSession) },
      });
      expect(res.status).toBe(401);
    });
  });

  describe("/api gate (ui scope)", () => {
    it("rejects an mcp-scoped token on the user API", async () => {
      // /api/* requires the `ui` scope — an mcp token must not reach it.
      const res = await fetch(`${appServer.url}/api/keys`, {
        headers: { authorization: `Bearer ${appServer.apiKey}` },
      });
      expect(res.status).toBe(403);
    });

    it("accepts the ui-scoped token on the user API", async () => {
      const res = await fetch(`${appServer.url}/api/keys`, {
        headers: { authorization: `Bearer ${appServer.uiToken}` },
      });
      expect(res.status).toBe(200);
    });

    it("does not accept a subprotocol-smuggled token outside /ws (F10)", async () => {
      // The Sec-WebSocket-Protocol token fallback is scoped to /ws only. On
      // /api/* the Authorization header is required — a valid ui token offered
      // via the subprotocol must NOT authenticate.
      const res = await fetch(`${appServer.url}/api/keys`, {
        headers: { "sec-websocket-protocol": `shellwatch.bearer, ${appServer.uiToken}` },
      });
      expect(res.status).toBe(401);
    });
  });
});
