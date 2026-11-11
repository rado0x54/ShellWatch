// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * CIMD front door against the real stack (#242): what the authorization
 * endpoint does with a `client_id` it is given, proven end to end rather than
 * in-process.
 *
 * A real HTTPS metadata-document host runs in-process (harness/cimd.ts) with a
 * throwaway CA the server is pointed at via `hydra.cimd.extraCaBundlePath` —
 * `SSL_CERT_FILE` would be the obvious hook but Go ignores it on macOS
 * (`root_unix.go` excludes darwin). That makes the whole path testable here:
 * fetch → validate → provision a Hydra client whose `client_id` IS the URL →
 * authorization_code + PKCE → an `mcp` token that reaches `/mcp`.
 *
 * The other half is refusing things safely, and the reason to run that against
 * a real Hydra rather than a fake is the assertion that closes each case:
 * nothing may be written to Hydra for a client that was refused.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HYDRA_ADMIN_URL, HYDRA_PUBLIC_URL, SPA_CLIENT_ID } from "../harness/env.js";
import { bootScenario, type Scenario } from "../harness/scenario.js";
import { Api, rawMcpPing } from "../harness/clients.js";
import {
  CookieJar,
  introspect,
  loginCimdClient,
  loginWebUi,
  stepUpToken,
  registerClient,
  selfRegister,
} from "../harness/oauth.js";
import { createPasskeyIdentity } from "../harness/identity.js";
import { recordScenario } from "../harness/out.js";
import { startDocumentHost, type DocumentHost } from "../harness/cimd.js";

/** One entry of the admin-only registration log (GET /api/audit/oauth-clients). */
interface LogRow {
  id: string;
  clientId: string;
  origin: "dcr" | "cimd";
  event: string;
  clientName: string | null;
  metadataHost: string | null;
  authMethod: string | null;
  redirectUris: string[];
  scope: string | null;
  reason: string | null;
  sourceIp: string | null;
  createdAt: string;
}

describe("CIMD front door (real Hydra) — discovery, passthrough, rejections", () => {
  let sc: Scenario;
  let host: DocumentHost;
  const rec = recordScenario("cimd", () => sc?.server);

  beforeAll(async () => {
    host = await startDocumentHost({
      client_name: "E2E CIMD Client",
      // The port-less loopback entries cover any ephemeral port the client
      // binds (RFC 8252 §7.3), which is what a native client needs.
      redirect_uris: ["http://127.0.0.1/callback", "http://[::1]/callback"],
      client_uri: "https://apps.example.com/",
      // Deliberately present: it must never reach Hydra or the consent page.
      logo_uri: "https://apps.example.com/logo.png",
    });
    sc = await bootScenario({
      scenario: "cimd",
      targets: [],
      // A second, non-admin account to prove the registration log is admin-only.
      selfRegistrationEnabled: true,
      cimd: {
        // The system trust store PLUS the document host's throwaway CA.
        extraCaBundlePath: host.caPath,
        // The host is on loopback, which the SSRF guard refuses by default.
        allowLoopbackDocuments: true,
        cacheMinSeconds: 1,
        cacheMaxSeconds: 2,
      },
    });
  });

  afterAll(async () => {
    await sc?.stop();
    await host?.stop();
  });

  /** GET the front door without following the hand-off, so Location is visible. */
  async function authorize(query: string): Promise<Response> {
    return fetch(`${sc.server.url}/api/hydra/authorize?${query}`, { redirect: "manual" });
  }

  async function log(params = ""): Promise<LogRow[]> {
    const res = await sc.api.get<{ rows: LogRow[] }>(
      `/api/audit/oauth-clients${params ? `?${params}` : ""}`,
    );
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    return res.body.rows;
  }

  /** Ask the real Hydra directly — the only way to prove nothing was written. */
  async function hydraClient(clientId: string): Promise<Record<string, unknown> | null> {
    const res = await fetch(`${HYDRA_ADMIN_URL}/admin/clients/${encodeURIComponent(clientId)}`);
    if (res.status === 404) return null;
    expect(res.status).toBe(200);
    return (await res.json()) as Record<string, unknown>;
  }

  async function hydraClientCount(): Promise<number> {
    const res = await fetch(`${HYDRA_ADMIN_URL}/admin/clients?page_size=250`);
    expect(res.status).toBe(200);
    return ((await res.json()) as unknown[]).length;
  }

  it("advertises the front door and CIMD support, with no shared-secret auth methods", async () => {
    const meta = (await (
      await fetch(`${sc.server.url}/.well-known/oauth-authorization-server`)
    ).json()) as Record<string, unknown>;

    expect(meta.client_id_metadata_document_supported).toBe(true);
    expect(meta.authorization_endpoint).toBe(`${sc.server.url}/api/hydra/authorize`);
    // Token/refresh/revoke stay Hydra's — CIMD changes authorization only.
    expect(meta.token_endpoint).toBe(`${HYDRA_PUBLIC_URL}/oauth2/token`);
    expect(meta.revocation_endpoint).toBe(`${HYDRA_PUBLIC_URL}/oauth2/revoke`);
    // ShellWatch issues no client secrets, and CIMD forbids them outright.
    expect(meta.token_endpoint_auth_methods_supported).toEqual(["none", "private_key_jwt"]);
    // DCR remains advertised as the deprecated fallback.
    expect(meta.registration_endpoint).toBe(`${sc.server.url}/api/hydra/register`);
  });

  it("passes a non-URL client_id through to Hydra with the query string byte-for-byte", async () => {
    // Deliberately awkward: duplicate keys, reserved characters, an empty value.
    const raw =
      `client_id=${SPA_CLIENT_ID}&response_type=code&scope=ui+offline_access&` +
      `redirect_uri=${encodeURIComponent(`${sc.server.url}/auth/callback`)}&` +
      `state=a%2Bb%26c%3Dd&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&` +
      `code_challenge_method=S256&prompt=&audience=x&audience=y`;
    const res = await authorize(raw);

    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(`${HYDRA_PUBLIC_URL}/oauth2/auth?${raw}`);
    expect(res.headers.get("cache-control")).toBe("no-store");
    rec.note(`passthrough → ${res.headers.get("location")}`);
  });

  it("passes a missing client_id through — Hydra owns that error", async () => {
    const res = await authorize("response_type=code");
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(`${HYDRA_PUBLIC_URL}/oauth2/auth?response_type=code`);
  });

  // draft-ietf-oauth-client-id-metadata-document-02 §3. A malformed https id
  // must produce a CIMD error, never a silent passthrough that Hydra would
  // reject with a confusing "unknown client".
  it.each([
    ["no path component", "https://apps.example.com"],
    ["root path only", "https://apps.example.com/"],
    ["a query component", "https://apps.example.com/c.json?x=1"],
    ["a fragment", "https://apps.example.com/c.json#f"],
    ["userinfo", "https://user@apps.example.com/c.json"],
    ["dot segments", "https://apps.example.com/a/../c.json"],
  ])("rejects a client_id URL with %s and renders rather than redirects", async (_what, id) => {
    const res = await authorize(
      new URLSearchParams({
        client_id: id,
        redirect_uri: "http://127.0.0.1:43999/callback",
        response_type: "code",
        state: "xyz",
      }).toString(),
    );
    expect(res.status).toBe(400);
    // The requested redirect_uri was never validated against a document, so it
    // must not be used as a destination.
    expect(res.headers.get("location")).toBeNull();
    expect(res.headers.get("content-type")).toContain("text/html");
  });

  // §8.6 — the dial-time guard. These must be refused without a single
  // outbound request leaving the host.
  it.each([
    ["cloud metadata", "https://169.254.169.254/latest/meta-data/client.json"],
    ["RFC 1918", "https://10.0.0.1/client.json"],
    ["loopback (allowLoopbackDocuments defaults off)", "https://127.0.0.1/client.json"],
    ["IPv6 loopback", "https://[::1]/client.json"],
    ["link-local v6", "https://[fe80::1]/client.json"],
  ])("refuses an SSRF destination: %s", async (_what, id) => {
    const res = await authorize(new URLSearchParams({ client_id: id }).toString());
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
  });

  it("aborts when the document host does not resolve", async () => {
    // .invalid never resolves (RFC 2606), so this exercises the fetch-failure
    // path rather than the address guard.
    const res = await authorize(
      new URLSearchParams({ client_id: "https://nonexistent.invalid/client.json" }).toString(),
    );
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
  });

  it("writes nothing to Hydra for any refused client, and logs each refusal", async () => {
    const rejected = await log("event=rejected");
    expect(rejected.length).toBeGreaterThanOrEqual(10);
    expect(rejected.every((r) => r.origin === "cimd")).toBe(true);

    // Each refusal records why, and the hostname — the identity cue §9.1 wants
    // surfaced, and the only part of a URL client_id an attacker cannot choose.
    for (const row of rejected) {
      expect(row.reason, JSON.stringify(row)).toBeTruthy();
      expect(row.clientName).toBeNull();
      expect(row.redirectUris).toEqual([]);
      expect(row.sourceIp).toBeTruthy();
    }
    const byHost = Object.fromEntries(rejected.map((r) => [r.metadataHost, r]));
    expect(byHost["169.254.169.254"]?.reason).toMatch(/invalid_client/);
    expect(byHost["nonexistent.invalid"]?.reason).toMatch(/unavailable/);
    expect(byHost["apps.example.com"]).toBeTruthy();

    // Not one of them exists in Hydra.
    for (const row of rejected) {
      expect(await hydraClient(row.clientId), `${row.clientId} must not exist`).toBeNull();
    }
    rec.note(`${rejected.length} rejections logged, none provisioned`);
  });

  it("completes authorization for a URL client_id with no registration call, and the token reaches /mcp", async () => {
    const before = host.hits();
    const login = await loginCimdClient({
      clientId: host.clientId,
      scope: "mcp",
      identity: sc.identity,
      // An ephemeral loopback port, matched against the document's port-less
      // entry by the RFC 8252 §7.3 exception.
      redirectUri: "http://127.0.0.1:45678/callback",
    });
    expect(host.hits()).toBeGreaterThan(before);
    expect(host.requests().at(-1)?.accept).toBe("application/json");

    // The token's client is the URL itself — that is the whole point.
    const t = await introspect(login.tokens.access_token);
    expect(t).toMatchObject({ active: true, sub: sc.accountId, client_id: host.clientId });
    expect(t.scope?.split(" ")).toEqual(expect.arrayContaining(["mcp", "offline_access"]));
    expect(login.tokens.refresh_token).toBeTruthy();

    // Acceptance criterion: a CIMD-only client reaches /mcp.
    expect(await rawMcpPing(login.tokens.access_token)).not.toBe(401);

    // Hydra holds a client whose client_id is the URL, marked as CIMD-origin,
    // with the document's redirect URIs and the policy-filtered scope.
    const client = await hydraClient(host.clientId);
    expect(client).not.toBeNull();
    expect(client?.client_id).toBe(host.clientId);
    expect(client?.client_name).toBe("E2E CIMD Client");
    expect(client?.token_endpoint_auth_method).toBe("none");
    expect(client?.scope).toBe("mcp offline_access");
    expect(client?.redirect_uris).toEqual(["http://127.0.0.1/callback", "http://[::1]/callback"]);
    expect((client?.metadata as Record<string, unknown>)?.shellwatch).toMatchObject({
      origin: "cimd",
    });
    // §9.3 — the document's logo_uri must not have been carried into Hydra.
    expect(JSON.stringify(client)).not.toContain("logo.png");

    const rows = await log(`clientId=${encodeURIComponent(host.clientId)}`);
    expect(rows[rows.length - 1]).toMatchObject({
      origin: "cimd",
      event: "registered",
      clientName: "E2E CIMD Client",
      metadataHost: "127.0.0.1",
      authMethod: "none",
    });
    rec.note(`CIMD login: ${login.trace.steps.join(" | ")}`);
  });

  it("re-approves every authorization for a URL client_id — the silent skip is refused", async () => {
    // Same browser as the admin's web login, so Hydra has a remembered session
    // AND remembered consent for this client from the previous test.
    const jar = new CookieJar();
    const first = await loginCimdClient({
      clientId: host.clientId,
      scope: "mcp",
      identity: sc.identity,
      jar,
    });
    expect(first.tokens.access_token).toBeTruthy();

    const second = await loginCimdClient({
      clientId: host.clientId,
      scope: "mcp",
      identity: sc.identity,
      jar,
    });
    // The login itself may be remembered, but consent is asked again — a
    // metadata document can change between authorizations.
    expect(second.trace.loginSkipped).toBe(true);
    expect(second.trace.consent).not.toBe("none");
    expect(second.tokens.access_token).toBeTruthy();

    // Remembering is still on, which is what keeps the client listed and
    // revocable under Settings → Authorized clients.
    const listed = await sc.api.get<{ sessions: { clientId: string }[] }>("/api/auth/sessions");
    expect(listed.status).toBe(200);
    expect(listed.body.sessions.map((x) => x.clientId)).toContain(host.clientId);
  });

  it("leads the consent page with the client_id hostname and renders no remote logo", async () => {
    let html = "";
    await loginCimdClient({
      clientId: host.clientId,
      scope: "mcp",
      identity: sc.identity,
      // A fresh browser, so consent is actually rendered rather than skipped.
      jar: new CookieJar(),
      onConsentHtml: (h) => {
        html = h;
      },
    });
    expect(html, "the consent page must be rendered for a CIMD client").not.toBe("");

    // The hostname is shown, and before the self-assigned name.
    const hostIdx = html.indexOf("127.0.0.1");
    const nameIdx = html.indexOf("E2E CIMD Client");
    expect(hostIdx).toBeGreaterThanOrEqual(0);
    expect(nameIdx).toBeGreaterThan(hostIdx);
    expect(html).toContain('class="cimd-host"');
    expect(html).toContain("calls itself");
    // client_uri's host differs from the client_id host, which is worth seeing.
    expect(html).toContain("apps.example.com");
    // §9.3: no client-supplied image, ever — the only <img> is ShellWatch's own.
    expect(html).not.toContain("logo.png");
    for (const tag of html.split("<img").slice(1)) {
      expect(tag.slice(0, tag.indexOf(">"))).toContain('src="/logo.svg"');
    }
    // Freshly provisioned, so the "recently changed" hint is shown.
    expect(html).toContain("less than an hour ago");
  });

  it("refreshes the Hydra client when the document changes, and logs the refresh", async () => {
    host.setDocument({
      client_name: "E2E CIMD Client v2",
      redirect_uris: ["http://127.0.0.1/callback", "http://[::1]/callback"],
      client_uri: "https://apps.example.com/",
    });
    // cacheMaxSeconds is 2 in this scenario, so the cached document expires.
    await new Promise((r) => setTimeout(r, 2500));

    await loginCimdClient({
      clientId: host.clientId,
      scope: "mcp",
      identity: sc.identity,
    });

    const client = await hydraClient(host.clientId);
    expect(client?.client_name).toBe("E2E CIMD Client v2");

    const rows = await log(`clientId=${encodeURIComponent(host.clientId)}`);
    expect(rows.map((r) => r.event)).toContain("refreshed");
    // History is not rewritten: the original registration row is still there
    // with the old name.
    const registered = rows.filter((r) => r.event === "registered");
    expect(registered).toHaveLength(1);
    expect(registered[0].clientName).toBe("E2E CIMD Client");
  });

  it("refuses a document that fails validation, leaving the existing client untouched", async () => {
    // A shared-secret auth method is forbidden outright (draft §4.1).
    host.setDocument({
      client_name: "E2E CIMD Client v2",
      redirect_uris: ["http://127.0.0.1/callback"],
      token_endpoint_auth_method: "client_secret_basic",
    });
    await new Promise((r) => setTimeout(r, 2500));

    const res = await authorize(
      new URLSearchParams({
        client_id: host.clientId,
        redirect_uri: "http://127.0.0.1:45680/callback",
        state: "bad-doc",
      }).toString(),
    );
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();

    // The previously provisioned client is unchanged — a bad refresh must not
    // damage a working registration.
    const client = await hydraClient(host.clientId);
    expect(client?.client_name).toBe("E2E CIMD Client v2");
    expect(client?.token_endpoint_auth_method).toBe("none");

    const rejected = await log(`clientId=${encodeURIComponent(host.clientId)}&event=rejected`);
    expect(rejected.length).toBeGreaterThanOrEqual(1);
    expect(rejected[0].reason).toMatch(/not supported|client_secret/);
  });

  it("records a mediated DCR registration and stamps its origin on the Hydra client", async () => {
    const before = await hydraClientCount();
    const dcr = await registerClient({
      clientName: "E2E CIMD-log DCR",
      redirectUri: "http://127.0.0.1:43998/cb",
      scope: "mcp",
    });
    expect(await hydraClientCount()).toBe(before + 1);

    const rows = await log(`clientId=${encodeURIComponent(dcr.client_id)}`);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      clientId: dcr.client_id,
      origin: "dcr",
      event: "registered",
      clientName: "E2E CIMD-log DCR",
      authMethod: "none",
      // DCR has no metadata document, so no host.
      metadataHost: null,
    });
    expect(rows[0].scope?.split(" ")).toEqual(expect.arrayContaining(["mcp", "offline_access"]));
    expect(rows[0].redirectUris).toEqual(["http://127.0.0.1:43998/cb"]);

    // Hydra's own client list can now tell DCR from CIMD.
    const client = await hydraClient(dcr.client_id);
    expect(client?.metadata).toEqual({ shellwatch: { origin: "dcr" } });
  });

  it("refuses a DCR registration that fails the shared redirect-URI policy, and logs nothing", async () => {
    const before = (await log()).length;
    await expect(
      registerClient({
        clientName: "E2E policy violation",
        redirectUri: "https://evil.example.net/cb",
        scope: "mcp",
      }),
    ).rejects.toThrow(/invalid_redirect_uri/);
    // A policy refusal is answered inline and carries no client_id, so there is
    // nothing an admin could act on that the 400 does not already say.
    expect((await log()).length).toBe(before);
  });

  it("the registration log is admin-only — it is the one audit surface that is not account-scoped", async () => {
    const other = createPasskeyIdentity("E2E non-admin");
    const { accountId } = await selfRegister(other, "Non Admin");
    expect(accountId).not.toBe(sc.accountId);
    const nonAdmin = new Api((await loginWebUi(other)).tokens.access_token);

    const me = await nonAdmin.get<{ isAdmin: boolean }>("/api/auth/me");
    expect(me.status).toBe(200);
    expect(me.body.isAdmin).toBe(false);

    const denied = await nonAdmin.get<{ error: string }>("/api/audit/oauth-clients");
    expect(denied.status).toBe(403);
    expect(denied.body.error).toBe("Admin role required");
    // Nothing leaks alongside the refusal.
    expect(denied.body).not.toHaveProperty("rows");

    // The account-scoped audit surfaces stay readable for the same caller, so
    // the 403 is about this log specifically and not a broken token.
    expect((await nonAdmin.get("/api/audit/sessions")).status).toBe(200);
  });

  it("paginates the log newest-first with a stable keyset cursor", async () => {
    const first = await sc.api.get<{ rows: LogRow[]; nextCursor: string | null }>(
      "/api/audit/oauth-clients?limit=3",
    );
    expect(first.status).toBe(200);
    expect(first.body.rows).toHaveLength(3);
    expect(first.body.nextCursor).toBeTruthy();

    const seen = new Set(first.body.rows.map((r) => r.id));
    let cursor = first.body.nextCursor;
    let pages = 0;
    while (cursor && pages < 20) {
      const next = await sc.api.get<{ rows: LogRow[]; nextCursor: string | null }>(
        `/api/audit/oauth-clients?limit=3&cursor=${encodeURIComponent(cursor)}`,
      );
      expect(next.status).toBe(200);
      for (const row of next.body.rows) {
        expect(seen.has(row.id), `row ${row.id} returned twice`).toBe(false);
        seen.add(row.id);
      }
      cursor = next.body.nextCursor;
      pages++;
    }
    expect(cursor).toBeNull();

    // Newest first, and the whole log is reachable by paging.
    const all = await log("limit=500");
    expect(seen.size).toBe(all.length);
    const times = all.map((r) => r.createdAt);
    expect([...times].sort().reverse()).toEqual(times);
  });

  // A CIMD client_id is a URL, so revocation has to survive being
  // percent-encoded into the route. chi hands the segment back still encoded,
  // which previously sent Hydra a client literally named "https%3A%2F%2F…".
  it("revokes a CIMD client by its URL client_id", async () => {
    const listed = await sc.api.get<{ sessions: { clientId: string }[] }>("/api/auth/sessions");
    expect(listed.status).toBe(200);
    expect(listed.body.sessions.map((x) => x.clientId)).toContain(host.clientId);

    const token = await stepUpToken(sc.uiToken, sc.identity, "revoke_session");
    const revoked = await sc.api.request(
      "DELETE",
      `/api/auth/sessions/${encodeURIComponent(host.clientId)}`,
      undefined,
      { "x-shellwatch-stepup-token": token },
    );
    expect(revoked.status, JSON.stringify(revoked.body)).toBe(200);
    expect(revoked.body).toEqual({ status: "revoked" });

    // Hydra really dropped the grant for THAT client.
    const after = await sc.api.get<{ sessions: { clientId: string }[] }>("/api/auth/sessions");
    expect(after.status).toBe(200);
    expect(after.body.sessions.map((x) => x.clientId)).not.toContain(host.clientId);
    // …and not for the web UI's own grant.
    expect(after.body.sessions.map((x) => x.clientId)).toContain(SPA_CLIENT_ID);
  });

  it("rejects an unknown origin or event filter rather than silently ignoring it", async () => {
    for (const q of ["origin=bogus", "event=bogus"]) {
      const res = await sc.api.get<{ error: string }>(`/api/audit/oauth-clients?${q}`);
      expect(res.status, q).toBe(400);
      expect(res.body.error).toMatch(/invalid (origin|event) filter/);
    }
  });
});
