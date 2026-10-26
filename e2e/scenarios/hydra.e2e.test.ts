// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Real Ory Hydra (#244): discovery parity with the committed goldens and with
 * Hydra's own metadata, the passkey login + consent provider branches
 * (fresh login → Approve; remembered login → passkey consent), DCR policy,
 * refresh-token rotation, revocation, and account-wide sign-out.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { normalizeGolden } from "../lib/golden.js";
import { HYDRA_PUBLIC_URL, REPO_ROOT, SPA_CLIENT_ID } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import { Api, rawMcpPing } from "../harness/clients.js";
import {
  CookieJar,
  hydraOpenIdConfiguration,
  introspect,
  loginThirdPartyClient,
  loginWebUi,
  refreshTokens,
  registerClient,
  revokeToken,
  stepUpToken,
} from "../harness/oauth.js";
import { recordScenario } from "../harness/out.js";

const GOLDENS = resolve(REPO_ROOT, "testdata/goldens");
/** The goldens pin the dev Hydra issuer; fold the e2e issuer onto it before comparing. */
const GOLDEN_HYDRA_URL = "http://localhost:4444";

describe("Hydra (real) — discovery, login/consent branches, tokens", () => {
  let sc: Scenario;
  const rec = recordScenario("hydra", () => sc?.server);

  beforeAll(async () => {
    sc = await bootScenario({ scenario: "hydra", targets: [] });
  });

  afterAll(async () => {
    await sc?.stop();
  });

  function golden(name: string): { status: number; body: unknown } {
    return JSON.parse(readFileSync(resolve(GOLDENS, `${name}.json`), "utf8")) as {
      status: number;
      body: unknown;
    };
  }

  async function discovery(path: string): Promise<{ status: number; body: unknown }> {
    const res = await fetch(`${sc.server.url}${path}`);
    const text = (await res.text()).split(HYDRA_PUBLIC_URL).join(GOLDEN_HYDRA_URL);
    return {
      status: res.status,
      body: normalizeGolden(JSON.parse(text), { baseUrls: [sc.server.url] }),
    };
  }

  it.each([
    ["discovery-authorization-server", "/.well-known/oauth-authorization-server"],
    ["discovery-protected-resource", "/.well-known/oauth-protected-resource"],
    ["discovery-protected-resource-mcp", "/.well-known/oauth-protected-resource/mcp"],
    ["discovery-protected-resource-agent", "/.well-known/oauth-protected-resource/agent-proxy"],
  ])("serves %s matching the committed golden", async (name, path) => {
    const live = await discovery(path);
    const expected = golden(name);
    expect(live.status).toBe(expected.status);
    expect(live.body).toEqual(expected.body);
  });

  it("agrees with Hydra's own openid-configuration on issuer and endpoints", async () => {
    const ours = (await (
      await fetch(`${sc.server.url}/.well-known/oauth-authorization-server`)
    ).json()) as Record<string, string>;
    const hydra = await hydraOpenIdConfiguration();
    expect(ours.issuer).toBe(hydra.issuer);
    expect(ours.token_endpoint).toBe(hydra.token_endpoint);
    expect(ours.authorization_endpoint).toBe(hydra.authorization_endpoint);
    expect(ours.jwks_uri).toBe(hydra.jwks_uri);
    expect(ours.revocation_endpoint).toBe(hydra.revocation_endpoint);
    // Hydra's native DCR is off; ours is the mediated endpoint.
    expect(hydra.registration_endpoint).toBeUndefined();
    expect(ours.registration_endpoint).toBe(`${sc.server.url}/api/hydra/register`);

    // RFC 9207 (#243): our blended doc must advertise
    // authorization_response_iss_parameter_supported exactly as truthfully as
    // Hydra does. Hydra v26.2.0 neither advertises it nor emits `iss` on the
    // authorization response; when a Hydra upgrade starts doing either, this
    // assertion flags the doc (and MCP clients' iss validation) for review.
    expect(ours.authorization_response_iss_parameter_supported).toBe(
      hydra.authorization_response_iss_parameter_supported,
    );
  });

  it("the authorization response carries RFC 9207 `iss` iff Hydra advertises it", async () => {
    const hydra = await hydraOpenIdConfiguration();
    const flow = await loginThirdPartyClient({
      clientName: "E2E iss probe",
      scope: "mcp",
      identity: sc.identity,
      jar: sc.jar,
    });
    if (hydra.authorization_response_iss_parameter_supported) {
      expect(flow.issParam).toBe(hydra.issuer);
    } else {
      expect(flow.issParam).toBeNull();
    }
  });

  it("the web UI login was a fresh passkey ceremony with first-party auto-consent and yields an introspectable ui token", async () => {
    const t = await introspect(sc.uiToken);
    expect(t).toMatchObject({ active: true, sub: sc.accountId, client_id: SPA_CLIENT_ID });
    expect(t.scope?.split(" ")).toEqual(expect.arrayContaining(["openid", "offline_access", "ui"]));
    expect(sc.uiTokens.refresh_token).toBeTruthy();
    expect(sc.uiTokens.id_token).toBeTruthy();
  });

  it("a remembered Hydra login skips the passkey; a third-party client then needs the passkey at consent", async () => {
    // Same "browser" (cookie jar) as the admin's web login.
    const again = await loginWebUi(sc.identity, sc.jar);
    expect(again.trace.loginSkipped).toBe(true);
    expect(again.trace.consent).toBe("first-party");

    const remembered = await loginThirdPartyClient({
      clientName: "E2E MCP (remembered)",
      scope: "mcp",
      identity: sc.identity,
      jar: sc.jar,
    });
    expect(remembered.trace.loginSkipped).toBe(true);
    expect(remembered.trace.consent).toBe("passkey");
    expect((await introspect(remembered.tokens.access_token)).scope?.split(" ")).toContain("mcp");

    // Fresh browser: passkey at login, so consent is a plain Approve click.
    const fresh = await loginThirdPartyClient({
      clientName: "E2E MCP (fresh)",
      scope: "mcp",
      identity: sc.identity,
      jar: new CookieJar(),
    });
    expect(fresh.trace.loginSkipped).toBe(false);
    expect(fresh.trace.consent).toBe("approve");
    rec.note(`fresh flow: ${fresh.trace.steps.join(" | ")}`);
  });

  it("mediated DCR enforces the redirect-URI and scope policy against the real Hydra", async () => {
    const ok = await registerClient({
      clientName: "E2E DCR",
      redirectUri: "http://127.0.0.1:43210/cb",
      scope: "agent",
    });
    expect(ok.token_endpoint_auth_method).toBe("none");
    expect(ok.scope.split(" ")).toEqual(expect.arrayContaining(["agent", "offline_access"]));

    await expect(
      registerClient({
        clientName: "evil",
        redirectUri: "https://evil.example.com/cb",
        scope: "mcp",
      }),
    ).rejects.toThrow(/invalid_redirect_uri/);
    const uiScope = await fetch(`${sc.server.url}/api/hydra/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["http://127.0.0.1:43211/cb"], scope: "ui" }),
    });
    expect(uiScope.status).toBe(400);
    expect(((await uiScope.json()) as { error: string }).error).toBe("invalid_scope");
  });

  it("rotates refresh tokens; reusing a consumed refresh token kills the whole grant", async () => {
    const { tokens } = await loginWebUi(sc.identity, new CookieJar());
    const rotated = await refreshTokens(SPA_CLIENT_ID, tokens.refresh_token!);
    expect(rotated.access_token).not.toBe(tokens.access_token);
    expect(rotated.refresh_token).toBeTruthy();
    expect(rotated.refresh_token).not.toBe(tokens.refresh_token);
    expect(rotated.scope?.split(" ")).toContain("ui");
    expect((await new Api(rotated.access_token).get("/api/auth/me")).status).toBe(200);

    // Rotation: the consumed refresh token is rejected — and Hydra treats the
    // replay as theft, revoking every token of the grant, so the freshly
    // rotated access token stops working at the server too.
    await expect(refreshTokens(SPA_CLIENT_ID, tokens.refresh_token!)).rejects.toMatchObject({
      status: expect.any(Number),
    });
    expect((await introspect(rotated.access_token)).active).toBe(false);
    const after = await new Api(rotated.access_token).get("/api/auth/me");
    expect(after.status).toBe(401);
    expect(after.headers.get("www-authenticate")).toContain('error="invalid_token"');
  });

  it("a token revoked at Hydra stops working at the server immediately (introspection cache off)", async () => {
    const { tokens } = await loginWebUi(sc.identity, new CookieJar());
    expect((await new Api(tokens.access_token).get("/api/auth/me")).status).toBe(200);
    expect(await revokeToken(SPA_CLIENT_ID, tokens.access_token)).toBe(200);
    expect((await introspect(tokens.access_token)).active).toBe(false);
    const after = await new Api(tokens.access_token).get("/api/auth/me");
    expect(after.status).toBe(401);
    expect(after.headers.get("www-authenticate")).toContain('error="invalid_token"');
    // Hydra revokes the whole grant with the access token: the refresh token is dead too.
    await expect(refreshTokens(SPA_CLIENT_ID, tokens.refresh_token!)).rejects.toMatchObject({
      status: 400,
    });
  });

  it("revoke-all (step-up gated) invalidates every grant including a live MCP token", async () => {
    const mcp = await loginThirdPartyClient({
      clientName: "E2E MCP (to revoke)",
      scope: "mcp",
      identity: sc.identity,
      jar: new CookieJar(),
    });
    expect(await rawMcpPing(mcp.tokens.access_token)).not.toBe(401);

    const listed = await sc.api.get<{
      sessions: { clientId: string; current: boolean; clientName: string }[];
    }>("/api/auth/sessions");
    expect(listed.status).toBe(200);
    expect(listed.body.sessions[0]).toMatchObject({ clientId: SPA_CLIENT_ID, current: true });
    expect(listed.body.sessions.map((s) => s.clientId)).toContain(mcp.clientId);

    const noStepUp = await sc.api.post<{ code: string }>("/api/auth/sessions/revoke-all");
    expect(noStepUp.status).toBe(401);
    expect(noStepUp.body.code).toBe("stepup_required");

    // A fresh ui token to act with — revoke-all kills the caller's own grant too.
    const actor = new Api((await loginWebUi(sc.identity, new CookieJar())).tokens.access_token);
    const token = await stepUpToken(actor.token!, sc.identity, "revoke_all_sessions");
    const revoked = await actor.post("/api/auth/sessions/revoke-all", undefined, {
      "x-shellwatch-stepup-token": token,
    });
    expect(revoked.status, JSON.stringify(revoked.body)).toBe(200);
    expect(revoked.body).toEqual({ status: "revoked_all" });

    expect((await introspect(mcp.tokens.access_token)).active).toBe(false);
    expect(await rawMcpPing(mcp.tokens.access_token)).toBe(401);
    expect((await actor.get("/api/auth/me")).status).toBe(401);
    // The remembered Hydra login is gone as well: the next web login is a fresh ceremony.
    const relogin = await loginWebUi(sc.identity, sc.jar);
    expect(relogin.trace.loginSkipped).toBe(false);
    // Hand the scenario a working token again for teardown-friendly state.
    sc.api = new Api(relogin.tokens.access_token);
  });
});
