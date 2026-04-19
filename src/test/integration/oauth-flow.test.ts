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
  }) {
    const formFields: Record<string, string> = {
      client_id: params.clientId ?? "sw-mcp",
      redirect_uri: params.redirectUri,
      state: params.state ?? "s",
      code_challenge: params.challenge,
      code_challenge_method: "S256",
    };
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

  it("exposes RFC 9728 protected-resource metadata pointing at /mcp", async () => {
    const res = await fetch(`${appServer.url}/.well-known/oauth-protected-resource`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.resource).toBe(`${appServer.url}/mcp`);
    expect(body.authorization_servers).toContain(appServer.url);
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
    expect(body.client_id).toBe("sw-mcp");
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.redirect_uris).toEqual(["http://127.0.0.1:54321/callback"]);
    expect(body.client_name).toBe("Claude Desktop");
  });

  it("MCP 401 includes WWW-Authenticate with resource_metadata pointer", async () => {
    const res = await fetch(`${appServer.url}/mcp`, { method: "POST" });
    expect(res.status).toBe(401);
    const challenge = res.headers.get("www-authenticate");
    expect(challenge).toContain("Bearer");
    expect(challenge).toContain(
      `resource_metadata="${appServer.url}/.well-known/oauth-protected-resource"`,
    );
  });

  it("GET /oauth/authorize without a session redirects to /login with returnTo preserved", async () => {
    const { challenge } = mkPkce();
    const originalPath =
      "/oauth/authorize?" +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-mcp",
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

  it("authorize page renders big redirect-URL warning + mode toggle", async () => {
    const { challenge } = mkPkce();
    const redirectUri = "http://totally-untrusted.example/cb";
    const authorizeUrl =
      `${appServer.url}/oauth/authorize?` +
      new URLSearchParams({
        response_type: "code",
        client_id: "sw-mcp",
        redirect_uri: redirectUri,
        state: "abc",
        code_challenge: challenge,
        code_challenge_method: "S256",
      }).toString();
    const pageRes = await fetch(authorizeUrl, { headers: authorizeHeaders() });
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    expect(html).toContain("Authorize MCP client");
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
        client_id: "sw-mcp",
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
    expect(html).toContain("Authorize MCP client");
  });

  it("POST authorize rejects a key that lacks the mcp scope", async () => {
    const { challenge } = mkPkce();
    const res = await submitAuthorize({
      apiKey: appServer.nonMcpApiKey,
      redirectUri: "http://127.0.0.1:54321/cb",
      challenge,
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/html/);
    const html = await res.text();
    expect(html).toContain("does not have");
    expect(html).toContain("scope");
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
        client_id: "sw-mcp",
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
          client_id: "sw-mcp",
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

    const before = await appServer.apiKeyRepo.findAll();
    const beforeCount = before.filter((k) => k.label === label).length;

    const submitRes = await submitAuthorize({
      redirectUri: "http://127.0.0.1:54321/cb",
      challenge,
      mode: "create",
      newKeyLabel: label,
    });
    expect(submitRes.status).toBe(302);
    // Intentionally do NOT call /oauth/token.

    const after = await appServer.apiKeyRepo.findAll();
    const afterCount = after.filter((k) => k.label === label).length;
    expect(afterCount).toBe(beforeCount);
  });

  it("create-mode: token exchange with wrong PKCE leaves NO key in the repo", async () => {
    const { challenge } = mkPkce();
    const redirectUri = "http://127.0.0.1:54321/cb";
    const label = `pkce-fail-${randomBytes(4).toString("hex")}`;

    const before = await appServer.apiKeyRepo.findAll();
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

    const after = await appServer.apiKeyRepo.findAll();
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

    const persisted = (await appServer.apiKeyRepo.findAll()).find((k) => k.label === label);
    expect(persisted).toBeDefined();
    expect(persisted!.scopes).toContain("mcp");
    expect(persisted!.keyPrefix).toBe((token.access_token as string).slice(0, 10));
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

      const prRes = await fetch(`${appServer.url}/.well-known/oauth-protected-resource`);
      const pr = await prRes.json();
      expect(pr.resource).toBe("https://oauth.example.com/mcp");
      expect(pr.authorization_servers).toEqual(["https://oauth.example.com"]);

      const mcpRes = await fetch(`${appServer.url}/mcp`, { method: "POST" });
      expect(mcpRes.status).toBe(401);
      expect(mcpRes.headers.get("www-authenticate")).toContain(
        "https://oauth.example.com/.well-known/oauth-protected-resource",
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
      mcpPath: "/mcp",
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
        clientId: "sw-mcp",
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
          client_id: "sw-mcp",
          redirect_uri: "http://127.0.0.1:54321/cb",
          state: "s",
          code_challenge: "abc",
          code_challenge_method: "plain",
        }).toString(),
      { headers: authorizeHeaders() },
    );
    expect(res.status).toBe(400);
  });
});
