// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { randomBytes } from "node:crypto";
import Fastify from "fastify";
import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import { InMemoryApiKeyRepository } from "../../db/index.js";
import { computePkceS256 } from "../../oauth/index.js";
import { registerOAuth } from "../../oauth/routes.js";
import { hashApiKey } from "../../server/auth/api-key-auth.js";
import { makeTestConfig } from "../helpers/test-config.js";
import {
  createTestLog,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

describe("OAuth DCR flow", () => {
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

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  function mkPkce() {
    const verifier = randomBytes(32).toString("base64url");
    return { verifier, challenge: computePkceS256(verifier) };
  }

  /** Authorize endpoints require a logged-in passkey session. */
  function authorizeHeaders(extra: Record<string, string> = {}): Record<string, string> {
    return { cookie: appServer.sessionCookie, ...extra };
  }

  async function submitAuthorize(params: {
    apiKey?: string;
    redirectUri: string;
    state?: string;
    challenge: string;
    clientId?: string;
    withSession?: boolean;
    mode?: "existing" | "create";
    newKeyLabel?: string;
    /** Raw scope string. Omit to exercise the default (mcp); accepts space-delimited list and unknown tokens. */
    scope?: string;
    /** RFC 8707 resource indicator. */
    resource?: string;
  }) {
    const formFields: Record<string, string> = {
      client_id: params.clientId ?? "sw-client",
      redirect_uri: params.redirectUri,
      state: params.state ?? "s",
      code_challenge: params.challenge,
      code_challenge_method: "S256",
    };
    if (params.scope) formFields.scope = params.scope;
    if (params.resource) formFields.resource = params.resource;
    const mode = params.mode ?? "existing";
    formFields.mode = mode;
    if (mode === "existing") {
      formFields.api_key = params.apiKey ?? appServer.apiKey;
    } else {
      if (params.newKeyLabel !== undefined) formFields.new_key_label = params.newKeyLabel;
    }
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };
    if (params.withSession !== false) headers.cookie = appServer.sessionCookie;
    return fetch(`${appServer.url}/oauth/authorize`, {
      method: "POST",
      headers,
      redirect: "manual",
      body: new URLSearchParams(formFields).toString(),
    });
  }

  it("exposes RFC 9728 protected-resource metadata at the unsuffixed legacy path (back-compat alias for /mcp)", async () => {
    const res = await fetch(`${appServer.url}/.well-known/oauth-protected-resource`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.resource).toBe(`${appServer.url}/mcp`);
    expect(body.authorization_servers).toContain(appServer.url);
    expect(body.bearer_methods_supported).toEqual(["header"]);
    expect(body.scopes_supported).toEqual(["mcp"]);
  });

  it("exposes RFC 9728 protected-resource metadata at the spec-correct /mcp path", async () => {
    const res = await fetch(`${appServer.url}/.well-known/oauth-protected-resource/mcp`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.resource).toBe(`${appServer.url}/mcp`);
    expect(body.authorization_servers).toContain(appServer.url);
    expect(body.bearer_methods_supported).toEqual(["header"]);
    expect(body.scopes_supported).toEqual(["mcp"]);
  });

  it("exposes RFC 9728 protected-resource metadata at /.well-known/oauth-protected-resource/agent-proxy", async () => {
    const res = await fetch(`${appServer.url}/.well-known/oauth-protected-resource/agent-proxy`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.resource).toBe(`${appServer.url}/agent-proxy`);
    expect(body.authorization_servers).toContain(appServer.url);
    expect(body.bearer_methods_supported).toEqual(["header"]);
    expect(body.scopes_supported).toEqual(["agent"]);
  });

  it("exposes RFC 8414 authorization-server metadata with all expected endpoints", async () => {
    const res = await fetch(`${appServer.url}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.issuer).toBe(appServer.url);
    expect(body.authorization_endpoint).toBe(`${appServer.url}/oauth/authorize`);
    expect(body.token_endpoint).toBe(`${appServer.url}/oauth/token`);
    expect(body.registration_endpoint).toBe(`${appServer.url}/oauth/register`);
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
    expect(body.token_endpoint_auth_methods_supported).toEqual(["none"]);
    expect(body.scopes_supported).toEqual(["agent", "mcp"]);
  });

  it("DCR stub accepts any registration without a session", async () => {
    const res = await fetch(`${appServer.url}/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "Claude Desktop",
        redirect_uris: ["http://127.0.0.1:54321/callback"],
      }),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.client_id).toBe("sw-client");
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.redirect_uris).toEqual(["http://127.0.0.1:54321/callback"]);
    expect(body.client_name).toBe("Claude Desktop");
  });

  it("MCP 401 includes WWW-Authenticate pointing at the /mcp resource metadata", async () => {
    const res = await fetch(`${appServer.url}/mcp`, { method: "POST" });
    expect(res.status).toBe(401);
    const challenge = res.headers.get("www-authenticate");
    expect(challenge).toContain("Bearer");
    expect(challenge).toContain(`realm="shellwatch"`);
    expect(challenge).toContain(
      `resource_metadata="${appServer.url}/.well-known/oauth-protected-resource/mcp"`,
    );
  });

  it("agent-proxy 401 includes WWW-Authenticate pointing at the /agent-proxy resource metadata", async () => {
    const res = await fetch(`${appServer.url}/agent-proxy`, { method: "GET" });
    expect(res.status).toBe(401);
    const challenge = res.headers.get("www-authenticate");
    expect(challenge).toContain("Bearer");
    expect(challenge).toContain(`realm="shellwatch"`);
    expect(challenge).toContain(
      `resource_metadata="${appServer.url}/.well-known/oauth-protected-resource/agent-proxy"`,
    );
  });

  it("GET /oauth/authorize without a session redirects to /login with returnTo preserved", async () => {
    const { challenge } = mkPkce();
    const originalPath =
      "/oauth/authorize?" +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-client",
        redirect_uri: "http://127.0.0.1:54321/cb",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }).toString();
    const res = await fetch(`${appServer.url}${originalPath}`, { redirect: "manual" });
    expect(res.status).toBe(302);
    const loc = res.headers.get("location")!;
    expect(loc.startsWith("/login?redirect=")).toBe(true);
    const redirectParam = new URLSearchParams(loc.split("?")[1]).get("redirect");
    expect(redirectParam).toBe(originalPath);
  });

  it("POST /oauth/authorize without a session redirects to /login (no code issued)", async () => {
    const { challenge } = mkPkce();
    const res = await submitAuthorize({
      redirectUri: "http://127.0.0.1:54321/cb",
      challenge,
      withSession: false,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")!.startsWith("/login?redirect=")).toBe(true);
  });

  it("authorize page renders big redirect-URL warning + mode toggle (defaults to create)", async () => {
    const { challenge } = mkPkce();
    const redirectUri = "http://totally-untrusted.example/cb";
    const authorizeUrl =
      `${appServer.url}/oauth/authorize?` +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-client",
        redirect_uri: redirectUri,
        state: "abc",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }).toString();
    const pageRes = await fetch(authorizeUrl, { headers: authorizeHeaders() });
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    expect(html).toContain("Authorize client");
    expect(html).toContain(redirectUri);
    expect(html).toContain("does NOT verify");
    // Client name row is no longer part of the page
    expect(html).not.toContain("Client name:");
    // Mode toggle + both fields rendered
    expect(html).toContain('name="mode" value="existing"');
    expect(html).toContain('name="mode" value="create"');
    expect(html).toContain('name="api_key"');
    expect(html).toContain('name="new_key_label"');
    expect(html).toContain(`value="abc"`);
    expect(html).toContain(`value="${challenge}"`);
    // Default mode is "create": the user shouldn't have to know about API
    // keys to get one. The "existing" radio must NOT be pre-selected and the
    // "create" radio MUST be pre-selected.
    expect(html).toContain('name="mode" value="create" checked');
    expect(html).not.toContain('name="mode" value="existing" checked');
    // No scope in the request → default to mcp.
    expect(html).toContain("<strong>Issued scopes:</strong> mcp");
    expect(html).not.toContain("<strong>Requested:</strong>");
  });

  it("scope=agent: issues agent scope only", async () => {
    const { challenge } = mkPkce();
    const authorizeUrl =
      `${appServer.url}/oauth/authorize?` +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-client",
        redirect_uri: "http://127.0.0.1:54321/cb",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
        scope: "agent",
      }).toString();
    const pageRes = await fetch(authorizeUrl, { headers: authorizeHeaders() });
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    expect(html).toContain("<strong>Issued scopes:</strong> agent");
    // Hidden field round-trips the raw client request for re-render display
    expect(html).toContain('name="scope" value="agent"');
    // No "not enabled" notice when the scope is actually grantable.
    expect(html).not.toContain('class="notice"');
    // Agent-only flows are launched by `shellwatch-agent login` — point the
    // user at that label rather than the historical "Claude Desktop" hint.
    expect(html).toContain('placeholder="e.g. shellwatch-agent"');
    expect(html).not.toContain('placeholder="e.g. Claude Desktop"');
  });

  it("scope=mcp+agent: keeps the historical placeholder (multi-scope is not agent-only)", async () => {
    const { challenge } = mkPkce();
    const authorizeUrl =
      `${appServer.url}/oauth/authorize?` +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-client",
        redirect_uri: "http://127.0.0.1:54321/cb",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
        scope: "mcp agent",
      }).toString();
    const pageRes = await fetch(authorizeUrl, { headers: authorizeHeaders() });
    const html = await pageRes.text();
    expect(html).toContain('placeholder="e.g. Claude Desktop"');
  });

  it("default scope (no scope param): keeps the historical placeholder", async () => {
    const { challenge } = mkPkce();
    const authorizeUrl =
      `${appServer.url}/oauth/authorize?` +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-client",
        redirect_uri: "http://127.0.0.1:54321/cb",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }).toString();
    const pageRes = await fetch(authorizeUrl, { headers: authorizeHeaders() });
    const html = await pageRes.text();
    expect(html).toContain('placeholder="e.g. Claude Desktop"');
  });

  it("scope=mcp agent: issues both scopes (sorted)", async () => {
    const { challenge } = mkPkce();
    const authorizeUrl =
      `${appServer.url}/oauth/authorize?` +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-client",
        redirect_uri: "http://127.0.0.1:54321/cb",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
        scope: "mcp agent",
      }).toString();
    const pageRes = await fetch(authorizeUrl, { headers: authorizeHeaders() });
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    expect(html).toContain("<strong>Issued scopes:</strong> agent mcp");
  });

  it("unknown scope tokens default to mcp and show the raw request", async () => {
    const { challenge } = mkPkce();
    const authorizeUrl =
      `${appServer.url}/oauth/authorize?` +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-client",
        redirect_uri: "http://127.0.0.1:54321/cb",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
        scope: "mcp:tools wat",
      }).toString();
    const pageRes = await fetch(authorizeUrl, { headers: authorizeHeaders() });
    // No invalid_scope rejection — fall back to mcp default + show raw.
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    expect(html).toContain("<strong>Issued scopes:</strong> mcp");
    expect(html).toContain("<strong>Requested:</strong> mcp:tools wat");
  });

  it("partial-match scope keeps recognized tokens, drops unknown ones", async () => {
    const { challenge } = mkPkce();
    const authorizeUrl =
      `${appServer.url}/oauth/authorize?` +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-client",
        redirect_uri: "http://127.0.0.1:54321/cb",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
        scope: "mcp:tools agent",
      }).toString();
    const pageRes = await fetch(authorizeUrl, { headers: authorizeHeaders() });
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    expect(html).toContain("<strong>Issued scopes:</strong> agent");
    expect(html).toContain("<strong>Requested:</strong> mcp:tools agent");
  });

  it("full round-trip: authorize → submit → exchange → hit /mcp", async () => {
    const { verifier, challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/callback";
    const state = "state-" + randomBytes(8).toString("hex");

    const submitRes = await submitAuthorize({ redirectUri, state, challenge });
    expect(submitRes.status).toBe(302);
    const location = submitRes.headers.get("location")!;
    const locUrl = new URL(location);
    expect(locUrl.origin + locUrl.pathname).toBe(redirectUri);
    expect(locUrl.searchParams.get("state")).toBe(state);
    const code = locUrl.searchParams.get("code");
    expect(code).toBeTruthy();

    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: redirectUri,
        code_verifier: verifier,
        client_id: "sw-client",
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    expect(tokenRes.headers.get("cache-control")).toBe("no-store");
    expect(tokenRes.headers.get("pragma")).toBe("no-cache");
    const token = await tokenRes.json();
    expect(token.token_type).toBe("Bearer");
    expect(token.access_token).toBe(appServer.apiKey);
    expect(token.refresh_token).toBeUndefined();

    const mcpRes = await fetch(`${appServer.url}/mcp`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "oauth-test", version: "0.0.0" },
        },
      }),
    });
    expect(mcpRes.status).not.toBe(401);
  });

  it("POST authorize with an unknown API key re-renders the form with an error", async () => {
    const { challenge } = mkPkce();
    const res = await submitAuthorize({
      apiKey: "sw_not_a_real_key_xxxxxxxxxxxxxx",
      redirectUri: "http://127.0.0.1:54321/cb",
      challenge,
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const html = await res.text();
    expect(html).toContain("not recognized");
    expect(html).toContain("Authorize client");
  });

  it("POST authorize rejects a key that lacks the mcp scope (default scope = mcp)", async () => {
    const { challenge } = mkPkce();
    const res = await submitAuthorize({
      apiKey: appServer.nonMcpApiKey, // agent-only
      redirectUri: "http://127.0.0.1:54321/cb",
      challenge,
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const html = await res.text();
    expect(html).toContain("missing required scope");
    // Apostrophes are HTML-escaped in the rendered banner.
    expect(html).toContain("&#39;mcp&#39;");
  });

  it("POST authorize with empty api_key re-renders the form", async () => {
    const { challenge } = mkPkce();
    const res = await submitAuthorize({
      apiKey: "",
      redirectUri: "http://127.0.0.1:54321/cb",
      challenge,
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Enter an API key");
  });

  it("rejects token exchange with wrong PKCE verifier", async () => {
    const { challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/callback";

    const submitRes = await submitAuthorize({ redirectUri, challenge });
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: "x".repeat(64),
        client_id: "sw-client",
      }).toString(),
    });
    expect(tokenRes.status).toBe(400);
    expect(tokenRes.headers.get("cache-control")).toBe("no-store");
    const body = await tokenRes.json();
    expect(body.error).toBe("invalid_grant");
  });

  it("rejects token exchange with mismatched redirect_uri", async () => {
    const { verifier, challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/callback";

    const submitRes = await submitAuthorize({ redirectUri, challenge });
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: "http://127.0.0.1:99999/different",
        code_verifier: verifier,
      }).toString(),
    });
    expect(tokenRes.status).toBe(400);
  });

  it("rejects re-use of an already-consumed code", async () => {
    const { verifier, challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/callback";

    const submitRes = await submitAuthorize({ redirectUri, challenge });
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;

    const first = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    expect(first.status).toBe(200);

    const second = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    expect(second.status).toBe(400);
  });

  it("rejects javascript: redirect_uri at authorize-GET", async () => {
    const { challenge } = mkPkce();
    const res = await fetch(
      `${appServer.url}/oauth/authorize?` +
        new URLSearchParams({
          response_type: "code",
          client_id: "sw-client",
          redirect_uri: "javascript:alert(1)",
          state: "s",
          code_challenge: challenge,
          code_challenge_method: "S256",
        }).toString(),
      { headers: authorizeHeaders() },
    );
    expect(res.status).toBe(400);
  });

  it("create-mode: issues a fresh sw_ key with mcp scope and completes the OAuth flow", async () => {
    const { verifier, challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/callback";
    const label = "Test MCP Client — created inline";

    const submitRes = await submitAuthorize({
      redirectUri,
      challenge,
      mode: "create",
      newKeyLabel: label,
    });
    expect(submitRes.status).toBe(302);
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const token = await tokenRes.json();
    expect(token.token_type).toBe("Bearer");
    expect(token.access_token).toMatch(/^sw_[0-9a-f]{48}$/);
    // Key created here must differ from the pre-seeded test key
    expect(token.access_token).not.toBe(appServer.apiKey);

    // And it must work on /mcp
    const mcpRes = await fetch(`${appServer.url}/mcp`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "oauth-create-test", version: "0.0.0" },
        },
      }),
    });
    expect(mcpRes.status).not.toBe(401);
  });

  it("create-mode: abandoned flow (no token exchange) leaves NO key in the repo", async () => {
    const { challenge } = mkPkce();
    const label = `abandoned-${randomBytes(4).toString("hex")}`;

    const before = await appServer.apiKeyRepo.findAllForAccount(appServer.accountId);
    const beforeCount = before.filter((k) => k.label === label).length;

    const submitRes = await submitAuthorize({
      redirectUri: "http://127.0.0.1:54321/cb",
      challenge,
      mode: "create",
      newKeyLabel: label,
    });
    expect(submitRes.status).toBe(302);
    // Intentionally do NOT call /oauth/token.

    const after = await appServer.apiKeyRepo.findAllForAccount(appServer.accountId);
    const afterCount = after.filter((k) => k.label === label).length;
    expect(afterCount).toBe(beforeCount);
  });

  it("create-mode: token exchange with wrong PKCE leaves NO key in the repo", async () => {
    const { challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/cb";
    const label = `pkce-fail-${randomBytes(4).toString("hex")}`;

    const before = await appServer.apiKeyRepo.findAllForAccount(appServer.accountId);
    const beforeCount = before.filter((k) => k.label === label).length;

    const submitRes = await submitAuthorize({
      redirectUri,
      challenge,
      mode: "create",
      newKeyLabel: label,
    });
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: "x".repeat(64), // wrong
      }).toString(),
    });
    expect(tokenRes.status).toBe(400);

    const after = await appServer.apiKeyRepo.findAllForAccount(appServer.accountId);
    const afterCount = after.filter((k) => k.label === label).length;
    expect(afterCount).toBe(beforeCount);
  });

  it("create-mode: successful token exchange DOES persist the key under the given label", async () => {
    const { verifier, challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/cb";
    const label = `success-${randomBytes(4).toString("hex")}`;

    const submitRes = await submitAuthorize({
      redirectUri,
      challenge,
      mode: "create",
      newKeyLabel: label,
    });
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const token = await tokenRes.json();

    const persisted = (await appServer.apiKeyRepo.findAllForAccount(appServer.accountId)).find(
      (k) => k.label === label,
    );
    expect(persisted).toBeDefined();
    expect(persisted!.scopes).toContain("mcp");
    expect(persisted!.keyPrefix).toBe((token.access_token as string).slice(0, 10));
  });

  it("scope=agent: create-mode mints a key with agent scope (not mcp)", async () => {
    const { verifier, challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/cb";
    const label = `agent-${randomBytes(4).toString("hex")}`;

    const submitRes = await submitAuthorize({
      redirectUri,
      challenge,
      mode: "create",
      newKeyLabel: label,
      scope: "agent",
    });
    expect(submitRes.status).toBe(302);
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const token = await tokenRes.json();
    expect(token.access_token).toMatch(/^sw_[0-9a-f]{48}$/);

    const persisted = (await appServer.apiKeyRepo.findAllForAccount(appServer.accountId)).find(
      (k) => k.label === label,
    );
    expect(persisted).toBeDefined();
    expect(persisted!.scopes).toEqual(["agent"]);
    expect(persisted!.scopes).not.toContain("mcp");
  });

  it("scope=agent: existing-mode rejects an mcp-only pasted key", async () => {
    const { challenge } = mkPkce();
    const res = await submitAuthorize({
      apiKey: appServer.apiKey, // mcp-only
      redirectUri: "http://127.0.0.1:54321/cb",
      challenge,
      scope: "agent",
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const html = await res.text();
    expect(html).toContain("missing required scope");
    // Apostrophes are HTML-escaped in the rendered banner.
    expect(html).toContain("&#39;agent&#39;");
  });

  it("resource alone (no scope param) infers scope from /agent-proxy", async () => {
    const { verifier, challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/cb";
    const label = `resource-only-${randomBytes(4).toString("hex")}`;

    const submitRes = await submitAuthorize({
      redirectUri,
      challenge,
      mode: "create",
      newKeyLabel: label,
      resource: `${appServer.url}/agent-proxy`,
    });
    expect(submitRes.status).toBe(302);
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const persisted = (await appServer.apiKeyRepo.findAllForAccount(appServer.accountId)).find(
      (k) => k.label === label,
    );
    expect(persisted!.scopes).toEqual(["agent"]);
  });

  it("resource is shown in the meta box and round-tripped via hidden field", async () => {
    const { challenge } = mkPkce();
    const resource = `${appServer.url}/agent-proxy`;
    const authorizeUrl =
      `${appServer.url}/oauth/authorize?` +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-client",
        redirect_uri: "http://127.0.0.1:54321/cb",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource,
      }).toString();
    const pageRes = await fetch(authorizeUrl, { headers: authorizeHeaders() });
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    expect(html).toContain(`<strong>Resource:</strong> ${resource}`);
    expect(html).toContain(`name="resource" value="${resource}"`);
  });

  it("scope=mcp + resource=/agent-proxy issues both scopes (union, not conflict)", async () => {
    const { verifier, challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/cb";
    const label = `union-${randomBytes(4).toString("hex")}`;

    const submitRes = await submitAuthorize({
      redirectUri,
      challenge,
      mode: "create",
      newKeyLabel: label,
      scope: "mcp",
      resource: `${appServer.url}/agent-proxy`,
    });
    expect(submitRes.status).toBe(302);
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const persisted = (await appServer.apiKeyRepo.findAllForAccount(appServer.accountId)).find(
      (k) => k.label === label,
    );
    // Both signals contribute: scope=mcp adds mcp, resource=/agent-proxy adds agent.
    expect(persisted!.scopes.sort()).toEqual(["agent", "mcp"]);
  });

  it("resource pointing at an unknown path is shown verbatim and falls back to mcp", async () => {
    const { challenge } = mkPkce();
    const resource = `${appServer.url}/some-other-thing`;
    const authorizeUrl =
      `${appServer.url}/oauth/authorize?` +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-client",
        redirect_uri: "http://127.0.0.1:54321/cb",
        state: "s",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource,
      }).toString();
    const pageRes = await fetch(authorizeUrl, { headers: authorizeHeaders() });
    // No invalid_target — unknown resource is informational, scope falls back.
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    expect(html).toContain("<strong>Issued scopes:</strong> mcp");
    expect(html).toContain(`<strong>Resource:</strong> ${resource}`);
  });

  it("scope=agent: existing-mode accepts an agent-scoped pasted key", async () => {
    const { verifier, challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/cb";
    const submitRes = await submitAuthorize({
      apiKey: appServer.nonMcpApiKey, // agent-only
      redirectUri,
      challenge,
      scope: "agent",
    });
    expect(submitRes.status).toBe(302);
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const token = await tokenRes.json();
    // The pasted key flows through unchanged.
    expect(token.access_token).toBe(appServer.nonMcpApiKey);
  });

  it("existing-mode: a key with extra scopes is fine — only the requested ones must be present", async () => {
    // Use a multi-scope key (seed mcp+agent) when client asked only for mcp.
    const { verifier, challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/cb";
    const multiKey = `sw_${randomBytes(24).toString("hex")}`;
    await appServer.apiKeyRepo.create({
      id: `multi-${randomBytes(4).toString("hex")}`,
      accountId: appServer.accountId,
      label: "multi-scope",
      keyHash: hashApiKey(multiKey),
      keyPrefix: multiKey.slice(0, 10),
      scopes: ["mcp", "agent"],
    });

    const submitRes = await submitAuthorize({
      apiKey: multiKey,
      redirectUri,
      challenge,
      scope: "mcp", // client only asks for mcp
    });
    expect(submitRes.status).toBe(302);
    const code = new URL(submitRes.headers.get("location")!).searchParams.get("code")!;
    const tokenRes = await fetch(`${appServer.url}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const token = await tokenRes.json();
    expect(token.access_token).toBe(multiKey);
  });

  it("create-mode: rejects missing label and preserves create-mode selection on re-render", async () => {
    const { challenge } = mkPkce();
    const res = await submitAuthorize({
      redirectUri: "http://127.0.0.1:54321/cb",
      challenge,
      mode: "create",
      newKeyLabel: "",
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const html = await res.text();
    expect(html).toContain("provide a name");
    // The create radio must be pre-selected in the re-rendered form
    expect(html).toContain('name="mode" value="create" checked');
  });

  it("discovery metadata reflects config.server.externalUrl verbatim", async () => {
    const original = appServer.config.server.externalUrl;
    appServer.config.server.externalUrl = "https://oauth.example.com";
    try {
      const res = await fetch(`${appServer.url}/.well-known/oauth-authorization-server`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.issuer).toBe("https://oauth.example.com");
      expect(body.authorization_endpoint).toBe("https://oauth.example.com/oauth/authorize");
      expect(body.token_endpoint).toBe("https://oauth.example.com/oauth/token");
      expect(body.registration_endpoint).toBe("https://oauth.example.com/oauth/register");

      // All three protected-resource forms must reflect the new externalUrl.
      for (const path of [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource/agent-proxy",
      ]) {
        const prRes = await fetch(`${appServer.url}${path}`);
        const pr = await prRes.json();
        expect(pr.authorization_servers).toEqual(["https://oauth.example.com"]);
        expect(pr.resource.startsWith("https://oauth.example.com/")).toBe(true);
      }

      const mcpRes = await fetch(`${appServer.url}/mcp`, { method: "POST" });
      expect(mcpRes.status).toBe(401);
      expect(mcpRes.headers.get("www-authenticate")).toContain(
        "https://oauth.example.com/.well-known/oauth-protected-resource/mcp",
      );

      const agentRes = await fetch(`${appServer.url}/agent-proxy`);
      expect(agentRes.status).toBe(401);
      expect(agentRes.headers.get("www-authenticate")).toContain(
        "https://oauth.example.com/.well-known/oauth-protected-resource/agent-proxy",
      );
    } finally {
      appServer.config.server.externalUrl = original;
    }
  });

  it("/oauth/token rejects an expired authorization code (isolated app, short TTL)", async () => {
    const app = Fastify({ logger: false });
    const apiKeyRepo = new InMemoryApiKeyRepository();
    const storedKey = `sw_${randomBytes(24).toString("hex")}`;
    await apiKeyRepo.create({
      id: "expiry-test-key",
      accountId: "expiry-test-account",
      label: "Expiry Test",
      keyHash: hashApiKey(storedKey),
      keyPrefix: storedKey.slice(0, 10),
      scopes: ["mcp"],
    });
    const cfg = makeTestConfig({});
    const handle = registerOAuth({
      app,
      apiKeyRepo,
      config: cfg,
      codeTtlMs: 40,
    });
    await app.listen({ port: 0, host: "127.0.0.1" });
    try {
      const addr = app.server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      const baseUrl = `http://127.0.0.1:${port}`;
      cfg.server.externalUrl = baseUrl;

      const { verifier, challenge } = mkPkce();
      const redirectUri = "http://127.0.0.1:1/cb";
      const code = handle._store.create({
        codeChallenge: challenge,
        codeChallengeMethod: "S256",
        pending: { kind: "existing", apiKey: storedKey },
        redirectUri,
        clientId: "sw-client",
      });

      await new Promise((resolve) => setTimeout(resolve, 80));

      const res = await fetch(`${baseUrl}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }).toString(),
      });
      expect(res.status).toBe(400);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const body = await res.json();
      expect(body.error).toBe("invalid_grant");
      expect(body.error_description).toMatch(/expired/i);
    } finally {
      handle.destroy();
      await app.close();
    }
  });

  it("rejects non-S256 PKCE at authorize-GET", async () => {
    const res = await fetch(
      `${appServer.url}/oauth/authorize?` +
        new URLSearchParams({
          response_type: "code",
          client_id: "sw-client",
          redirect_uri: "http://127.0.0.1:54321/cb",
          state: "s",
          code_challenge: "abc",
          code_challenge_method: "plain",
        }).toString(),
      { headers: authorizeHeaders() },
    );
    expect(res.status).toBe(400);
  });

  // Repeated query keys (?scope=mcp&scope=agent) and repeated form fields
  // become arrays under Fastify's qs parser. The handler used to crash on
  // these because it cast `req.query` to `Record<string, string>`. Make sure
  // the resolver handles arrays end-to-end.
  describe("array-valued scope/resource inputs", () => {
    it("handles repeated ?scope= keys without crashing", async () => {
      const { challenge } = mkPkce();
      const url =
        `${appServer.url}/oauth/authorize?` +
        new URLSearchParams([
          ["response_type", "code"],
          ["client_id", "sw-client"],
          ["redirect_uri", "http://127.0.0.1:54321/cb"],
          ["state", "s"],
          ["code_challenge", challenge],
          ["code_challenge_method", "S256"],
          ["scope", "mcp"],
          ["scope", "agent"],
        ]).toString();
      const res = await fetch(url, { headers: authorizeHeaders() });
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain("<strong>Issued scopes:</strong> agent mcp");
      // Display value joins repeated keys with a space.
      expect(html).toContain("<strong>Requested:</strong> mcp agent");
    });

    it("handles repeated ?resource= keys, unioning recognized scopes", async () => {
      const { challenge } = mkPkce();
      const url =
        `${appServer.url}/oauth/authorize?` +
        new URLSearchParams([
          ["response_type", "code"],
          ["client_id", "sw-client"],
          ["redirect_uri", "http://127.0.0.1:54321/cb"],
          ["state", "s"],
          ["code_challenge", challenge],
          ["code_challenge_method", "S256"],
          ["resource", `${appServer.url}/mcp`],
          ["resource", `${appServer.url}/agent-proxy`],
        ]).toString();
      const res = await fetch(url, { headers: authorizeHeaders() });
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain("<strong>Issued scopes:</strong> agent mcp");
    });
  });
});

// Separate describe block — needs its own app instance with proxyEnabled=false.
// The default startTestApp now enables the proxy so /agent-proxy is routable
// in tests; this suite verifies the disabled path.
describe("OAuth DCR flow with /agent-proxy disabled", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let appServer: TestAppServer;

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
    appServer = await startTestApp(sshServer, log, { agentProxyEnabled: false });
  });

  afterAll(async () => {
    await appServer?.close();
    await sshServer?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  it("does not advertise /agent-proxy in the AS scopes_supported", async () => {
    const res = await fetch(`${appServer.url}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.scopes_supported).toEqual(["mcp"]);
  });

  it("does not serve the /agent-proxy resource metadata doc", async () => {
    const res = await fetch(`${appServer.url}/.well-known/oauth-protected-resource/agent-proxy`);
    expect(res.status).toBe(404);
  });

  it("still serves the /mcp resource metadata doc and the legacy alias", async () => {
    for (const path of [
      "/.well-known/oauth-protected-resource",
      "/.well-known/oauth-protected-resource/mcp",
    ]) {
      const res = await fetch(`${appServer.url}${path}`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.scopes_supported).toEqual(["mcp"]);
    }
  });

  it("/agent-proxy 404s (no bearer-gate, no route) instead of misleadingly 401-ing", async () => {
    const res = await fetch(`${appServer.url}/agent-proxy`);
    expect(res.status).toBe(404);
  });

  it("scope=agent falls back to mcp and the page explains why", async () => {
    const challenge = computePkceS256(randomBytes(32).toString("base64url"));
    const res = await fetch(
      `${appServer.url}/oauth/authorize?` +
        new URLSearchParams({
          response_type: "code",
          client_id: "sw-client",
          redirect_uri: "http://127.0.0.1:54321/cb",
          state: "s",
          code_challenge: challenge,
          code_challenge_method: "S256",
          scope: "agent",
        }).toString(),
      { headers: { cookie: appServer.sessionCookie } },
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("<strong>Issued scopes:</strong> mcp");
    // Raw request is still surfaced for transparency.
    expect(html).toContain("<strong>Requested:</strong> agent");
    // And we now explain why the issued set diverges from what was requested.
    expect(html).toContain('class="notice"');
    expect(html).toContain("not enabled on this deployment");
  });

  it("resource=…/agent-proxy also surfaces the not-enabled notice", async () => {
    const challenge = computePkceS256(randomBytes(32).toString("base64url"));
    const res = await fetch(
      `${appServer.url}/oauth/authorize?` +
        new URLSearchParams({
          response_type: "code",
          client_id: "sw-client",
          redirect_uri: "http://127.0.0.1:54321/cb",
          state: "s",
          code_challenge: challenge,
          code_challenge_method: "S256",
          resource: `${appServer.url}/agent-proxy`,
        }).toString(),
      { headers: { cookie: appServer.sessionCookie } },
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("<strong>Issued scopes:</strong> mcp");
    expect(html).toContain('class="notice"');
    expect(html).toContain("not enabled on this deployment");
  });
});
