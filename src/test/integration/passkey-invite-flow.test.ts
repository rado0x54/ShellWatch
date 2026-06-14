// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Integration tests for the passkey-invite HTTP surface.
 *
 * What this exercises:
 *   - The state machine boundaries of the in-memory invite slot
 *     (single-use, supersede, expiry — via direct API calls).
 *   - The interaction between pending-credential rows and login (a pending
 *     credential MUST NOT pass either /api/auth/login/options or
 *     /api/auth/login).
 *   - Device A's confirm endpoint flips state and refuses already-active /
 *     revoked / non-existent credentials.
 *
 * What this does NOT exercise:
 *   - The actual WebAuthn ceremony (we'd need to fake an authenticator).
 *     The credential rows are written into the DB directly, simulating a
 *     successful ceremony, and the assertions focus on what the server does
 *     around it.
 *
 * Built on a thin per-test Fastify app rather than the full buildApp() so we
 * can spin up real SQLite + the auth gate + just the webauthn routes without
 * dragging in SSH transport, MCP, etc.
 */
import { randomUUID } from "node:crypto";
import fastifyRateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { rateLimitDefaults } from "../../config/schema.js";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { CREDENTIAL_STATE } from "../../db/repositories/index.js";
import { StubAccountRepository } from "../../db/repositories/account-repo.js";
import { accounts, webauthnCredentials } from "../../db/schema.js";
import { registerBearerGate } from "../../server/auth/bearer-gate.js";
import { createBearerResolver } from "../../hydra/bearer-resolver.js";
import type { FakeHydraAdmin } from "../helpers/fake-hydra.js";
import { makeTestBearer } from "../helpers/test-bearer.js";
import { makeTestConfig } from "../helpers/test-config.js";
import { registerHydraRoutes } from "../../hydra/routes.js";
import { _resetInviteStore } from "../../webauthn/invite-store.js";
import { registerWebAuthnRoutes } from "../../webauthn/routes.js";
import {
  _resetStepUpStore,
  mintStepUpToken,
  STEPUP_ACTION,
  type StepUpAction,
} from "../../webauthn/stepup-store.js";

const ACCOUNT_ID = "00000000-0000-0000-0000-00000000000a";

interface TestApp {
  app: FastifyInstance;
  conn: DatabaseConnection;
  auth: string;
  hydraAdmin: FakeHydraAdmin;
}

async function makeTestApp(): Promise<TestApp> {
  const conn = createDatabase(":memory:");
  runMigrations(conn.db);

  const now = new Date().toISOString();
  conn.db
    .insert(accounts)
    .values({ id: ACCOUNT_ID, name: "Test Account", createdAt: now, updatedAt: now })
    .run();

  const app = Fastify({ logger: false });
  app.decorateRequest("accountId", "");
  app.decorateRequest("apiKey", null);
  await app.register(fastifyRateLimit, { global: false });

  const accountRepo = new StubAccountRepository();
  const config = makeTestConfig();
  const { admin, bearerFor } = makeTestBearer();
  registerBearerGate({
    app,
    resolveBearer: createBearerResolver({ admin, cacheTtlMs: 0 }),
    accountRepo,
    config,
    agentProxyEnabled: false,
  });
  registerWebAuthnRoutes({
    app,
    db: conn.db,
    accountRepo,
    admin,
    rpId: "localhost",
    trustedOrigins: ["http://localhost"],
    selfRegistrationEnabled: false,
    rateLimitConfig: rateLimitDefaults,
  });
  // Mount the Hydra login provider so login-options/verify behavior (active-only
  // credentials, reject pending/revoked) is covered against the real endpoints.
  registerHydraRoutes({
    app,
    config,
    db: conn.db,
    accountRepo,
    admin,
    rpId: "localhost",
    trustedOrigins: ["http://localhost"],
    agentProxyEnabled: false,
  });

  await app.ready();

  return { app, conn, auth: bearerFor(ACCOUNT_ID), hydraAdmin: admin };
}

/**
 * Mint a step-up token for the calling account and return it as a header
 * fragment ready to spread into `inject({ headers })`. Saves repeating the
 * mint + header dance at every gated call site.
 */
function stepUpHeader(
  accountId: string,
  action: StepUpAction,
): { "x-shellwatch-stepup-token": string } {
  const minted = mintStepUpToken({ accountId, action });
  return { "x-shellwatch-stepup-token": minted.token };
}

function insertCredential(
  conn: DatabaseConnection,
  opts: {
    id?: string;
    credentialId?: string;
    label: string;
    state?: "active" | "pending_confirmation";
    revoked?: boolean;
  },
): { id: string; credentialId: string } {
  const id = opts.id ?? randomUUID();
  const credentialId = opts.credentialId ?? `webauthn-${id}`;
  conn.db
    .insert(webauthnCredentials)
    .values({
      id,
      accountId: ACCOUNT_ID,
      credentialId,
      publicKey: Buffer.alloc(0),
      label: opts.label,
      state: opts.state ?? CREDENTIAL_STATE.active,
      revoked: opts.revoked ?? false,
      createdAt: new Date().toISOString(),
    })
    .run();
  return { id, credentialId };
}

describe("passkey invite — HTTP integration", () => {
  let testApp: TestApp;

  beforeEach(async () => {
    _resetInviteStore();
    _resetStepUpStore();
    testApp = await makeTestApp();
  });

  afterEach(async () => {
    await testApp.app.close();
    testApp.conn.close();
    _resetInviteStore();
    _resetStepUpStore();
  });

  // ---- Invite slot state machine via HTTP ----

  it("create returns a token; GET-by-token resolves it", async () => {
    const created = await testApp.app.inject({
      method: "POST",
      url: "/api/webauthn/invite",
      headers: { authorization: testApp.auth, "content-type": "application/json" },
      payload: {},
    });
    expect(created.statusCode).toBe(200);
    const { invite } = created.json() as { invite: { token: string; expiresAt: string } };
    expect(invite.token).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const looked = await testApp.app.inject({
      method: "GET",
      url: `/api/passkey-invite/${invite.token}`,
    });
    expect(looked.statusCode).toBe(200);
    const meta = looked.json() as { accountName: string | null; expiresAt: string };
    expect(meta.accountName).toBe("Test Account");
    expect(typeof meta.expiresAt).toBe("string");
  });

  it("registration options use the account name as userName/userDisplayName", async () => {
    const created = await testApp.app.inject({
      method: "POST",
      url: "/api/webauthn/invite",
      headers: { authorization: testApp.auth, "content-type": "application/json" },
      payload: {},
    });
    const token = (created.json() as { invite: { token: string } }).invite.token;

    const opts = await testApp.app.inject({
      method: "POST",
      url: "/api/passkey-invite/register/options",
      headers: { "content-type": "application/json" },
      payload: { token },
    });
    expect(opts.statusCode).toBe(200);
    const body = opts.json() as { user: { name: string; displayName: string } };
    expect(body.user.name).toBe("Test Account");
    expect(body.user.displayName).toBe("Test Account");
  });

  it("creating a second invite supersedes the first — old token 404s", async () => {
    const first = await testApp.app.inject({
      method: "POST",
      url: "/api/webauthn/invite",
      headers: { authorization: testApp.auth, "content-type": "application/json" },
      payload: {},
    });
    const firstToken = (first.json() as { invite: { token: string } }).invite.token;

    const second = await testApp.app.inject({
      method: "POST",
      url: "/api/webauthn/invite",
      headers: { authorization: testApp.auth, "content-type": "application/json" },
      payload: {},
    });
    const secondToken = (second.json() as { invite: { token: string } }).invite.token;
    expect(secondToken).not.toBe(firstToken);

    const oldLookup = await testApp.app.inject({
      method: "GET",
      url: `/api/passkey-invite/${firstToken}`,
    });
    expect(oldLookup.statusCode).toBe(404);

    const newLookup = await testApp.app.inject({
      method: "GET",
      url: `/api/passkey-invite/${secondToken}`,
    });
    expect(newLookup.statusCode).toBe(200);
  });

  it("GET active-invite returns the slot; 404 once cleared", async () => {
    const empty = await testApp.app.inject({
      method: "GET",
      url: "/api/webauthn/invite",
      headers: { authorization: testApp.auth },
    });
    expect(empty.statusCode).toBe(404);

    await testApp.app.inject({
      method: "POST",
      url: "/api/webauthn/invite",
      headers: { authorization: testApp.auth, "content-type": "application/json" },
      payload: {},
    });

    const present = await testApp.app.inject({
      method: "GET",
      url: "/api/webauthn/invite",
      headers: { authorization: testApp.auth },
    });
    expect(present.statusCode).toBe(200);
  });

  it("public invite endpoints reject a bogus token", async () => {
    const lookup = await testApp.app.inject({
      method: "GET",
      url: "/api/passkey-invite/not-a-real-token",
    });
    expect(lookup.statusCode).toBe(404);

    const options = await testApp.app.inject({
      method: "POST",
      url: "/api/passkey-invite/register/options",
      headers: { "content-type": "application/json" },
      payload: { token: "not-a-real-token" },
    });
    expect(options.statusCode).toBe(404);

    const register = await testApp.app.inject({
      method: "POST",
      url: "/api/passkey-invite/register",
      headers: { "content-type": "application/json" },
      payload: { token: "not-a-real-token", challengeId: "x", credential: {} },
    });
    expect(register.statusCode).toBe(404);
  });

  it("invite create requires authentication (ui bearer token)", async () => {
    const res = await testApp.app.inject({
      method: "POST",
      url: "/api/webauthn/invite",
      headers: { "content-type": "application/json" },
      payload: {},
    });
    expect(res.statusCode).toBe(401);
  });

  // ---- Pending credential gating in login ----

  it("/api/auth/login/options excludes pending credentials", async () => {
    const active = insertCredential(testApp.conn, { label: "active-1" });
    insertCredential(testApp.conn, {
      label: "pending-1",
      state: "pending_confirmation",
    });

    const res = await testApp.app.inject({
      method: "POST",
      url: "/api/hydra/login/options",
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { allowCredentials?: { id: string }[] };
    const allow = body.allowCredentials ?? [];
    expect(allow.length).toBe(1);
    expect(allow[0]!.id).toBe(active.credentialId);
  });

  it("/api/auth/login refuses a pending credential before crypto", async () => {
    // Need at least one active credential to mint a challenge — login/options
    // returns `{ error: 'no_passkeys' }` otherwise. Once we have a challenge,
    // submit the pending credential's id and assert the state-check rejection
    // in login.ts fires before signature verification.
    insertCredential(testApp.conn, { label: "active-decoy" });
    const optionsRes = await testApp.app.inject({
      method: "POST",
      url: "/api/hydra/login/options",
    });
    const { challengeId } = optionsRes.json() as { challengeId: string };
    expect(challengeId).toBeTruthy();

    const pending = insertCredential(testApp.conn, {
      label: "pending",
      state: "pending_confirmation",
    });

    const verify = await testApp.app.inject({
      method: "POST",
      url: "/api/hydra/login/verify",
      headers: { "content-type": "application/json" },
      payload: {
        login_challenge: "dummy-challenge",
        challengeId,
        credential: {
          id: pending.credentialId,
          rawId: pending.credentialId,
          response: {},
          type: "public-key",
        },
      },
    });
    expect(verify.statusCode).toBe(403);
    const body = verify.json() as { error: string };
    expect(body.error.toLowerCase()).toContain("awaiting confirmation");
  });

  it("/api/auth/login refuses a revoked credential before crypto", async () => {
    insertCredential(testApp.conn, { label: "active-decoy" });
    const optionsRes = await testApp.app.inject({
      method: "POST",
      url: "/api/hydra/login/options",
    });
    const { challengeId } = optionsRes.json() as { challengeId: string };

    const revoked = insertCredential(testApp.conn, { label: "revoked", revoked: true });

    const verify = await testApp.app.inject({
      method: "POST",
      url: "/api/hydra/login/verify",
      headers: { "content-type": "application/json" },
      payload: {
        login_challenge: "dummy-challenge",
        challengeId,
        credential: {
          id: revoked.credentialId,
          rawId: revoked.credentialId,
          response: {},
          type: "public-key",
        },
      },
    });
    expect(verify.statusCode).toBe(403);
  });

  // ---- Confirm endpoint state transitions ----

  it("confirm flips a pending credential to active", async () => {
    const cred = insertCredential(testApp.conn, {
      label: "to-confirm",
      state: "pending_confirmation",
    });

    const res = await testApp.app.inject({
      method: "POST",
      url: `/api/webauthn/credentials/${cred.id}/confirm`,
      headers: {
        authorization: testApp.auth,
        ...stepUpHeader(ACCOUNT_ID, STEPUP_ACTION.confirmPasskey),
      },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { status: string }).status).toBe("active");

    const row = testApp.conn.db
      .select({ state: webauthnCredentials.state })
      .from(webauthnCredentials)
      .all()[0]!;
    expect(row.state).toBe(CREDENTIAL_STATE.active);
  });

  it("confirm 404s for an unknown credential id", async () => {
    const res = await testApp.app.inject({
      method: "POST",
      url: "/api/webauthn/credentials/does-not-exist/confirm",
      headers: {
        authorization: testApp.auth,
        ...stepUpHeader(ACCOUNT_ID, STEPUP_ACTION.confirmPasskey),
      },
    });
    expect(res.statusCode).toBe(404);
  });

  it("confirm refuses an already-active credential", async () => {
    const cred = insertCredential(testApp.conn, { label: "already-active" });
    const res = await testApp.app.inject({
      method: "POST",
      url: `/api/webauthn/credentials/${cred.id}/confirm`,
      headers: {
        authorization: testApp.auth,
        ...stepUpHeader(ACCOUNT_ID, STEPUP_ACTION.confirmPasskey),
      },
    });
    expect(res.statusCode).toBe(400);
  });

  it("confirm refuses a revoked credential", async () => {
    const cred = insertCredential(testApp.conn, {
      label: "revoked-pending",
      state: "pending_confirmation",
      revoked: true,
    });
    const res = await testApp.app.inject({
      method: "POST",
      url: `/api/webauthn/credentials/${cred.id}/confirm`,
      headers: {
        authorization: testApp.auth,
        ...stepUpHeader(ACCOUNT_ID, STEPUP_ACTION.confirmPasskey),
      },
    });
    expect(res.statusCode).toBe(400);
  });

  it("confirm refuses a credential belonging to a different account", async () => {
    const otherAccount = "00000000-0000-0000-0000-00000000000b";
    const now = new Date().toISOString();
    testApp.conn.db
      .insert(accounts)
      .values({ id: otherAccount, name: "Other", createdAt: now, updatedAt: now })
      .run();
    const id = randomUUID();
    testApp.conn.db
      .insert(webauthnCredentials)
      .values({
        id,
        accountId: otherAccount,
        credentialId: `webauthn-${id}`,
        publicKey: Buffer.alloc(0),
        label: "other-account-pending",
        state: CREDENTIAL_STATE.pendingConfirmation,
        createdAt: now,
      })
      .run();

    const res = await testApp.app.inject({
      method: "POST",
      url: `/api/webauthn/credentials/${id}/confirm`,
      headers: {
        authorization: testApp.auth,
        ...stepUpHeader(ACCOUNT_ID, STEPUP_ACTION.confirmPasskey),
      },
    });
    expect(res.statusCode).toBe(404);
  });

  // ---- Consent provider input validation: unauth 400, never 500 (#217) ----

  it("/api/hydra/consent/options returns 400 (not 500) for a missing challenge", async () => {
    const res = await testApp.app.inject({
      method: "POST",
      url: "/api/hydra/consent/options",
      headers: { "content-type": "application/json" },
      payload: {},
    });
    expect(res.statusCode).toBe(400);
  });

  it("/api/hydra/consent/options returns 400 (not 500) for a bogus challenge", async () => {
    // The fake Hydra admin rejects getConsentRequest → the handler must catch
    // and return 400, not let a HydraApiError bubble to a 500.
    const res = await testApp.app.inject({
      method: "POST",
      url: "/api/hydra/consent/options",
      headers: { "content-type": "application/json" },
      payload: { consent_challenge: "does-not-exist" },
    });
    expect(res.statusCode).toBe(400);
  });

  // ---- Provider GET pages + verify routes: 400 (HTML/JSON), never 500 (F3/F4) ----

  it("GET /api/hydra/login returns 400 for a missing login_challenge", async () => {
    const res = await testApp.app.inject({ method: "GET", url: "/api/hydra/login" });
    expect(res.statusCode).toBe(400);
    expect(res.headers["content-type"]).toContain("text/html");
  });

  it("GET /api/hydra/login returns 400 (not 500) for a bogus login_challenge", async () => {
    // getLoginRequest rejects (HydraApiError) → htmlFlow renders the error page
    // with 400 instead of letting it bubble to a 500 (and amplify admin calls).
    const res = await testApp.app.inject({
      method: "GET",
      url: "/api/hydra/login?login_challenge=does-not-exist",
    });
    expect(res.statusCode).toBe(400);
    expect(res.headers["content-type"]).toContain("text/html");
  });

  it("GET /api/hydra/consent returns 400 (not 500) for a bogus consent_challenge", async () => {
    const res = await testApp.app.inject({
      method: "GET",
      url: "/api/hydra/consent?consent_challenge=does-not-exist",
    });
    expect(res.statusCode).toBe(400);
    expect(res.headers["content-type"]).toContain("text/html");
  });

  it("POST /api/hydra/login/verify returns 400 (not 500) for a bodyless request", async () => {
    // No content-type / no body → request.body is undefined. Defensive reads
    // must yield a 400, not a TypeError-500 from destructuring first.
    const res = await testApp.app.inject({ method: "POST", url: "/api/hydra/login/verify" });
    expect(res.statusCode).toBe(400);
  });

  it("POST /api/hydra/consent/verify returns 400 (not 500) for a bodyless request", async () => {
    const res = await testApp.app.inject({ method: "POST", url: "/api/hydra/consent/verify" });
    expect(res.statusCode).toBe(400);
  });

  // ---- Option-1: one passkey, not two, on a fresh-login consent ----

  const seedConsent = (challenge: string, freshLogin: boolean) =>
    testApp.hydraAdmin.setConsentRequest(challenge, {
      challenge,
      skip: false,
      subject: ACCOUNT_ID,
      client: { client_id: "mcp-test-client", client_name: "Test MCP" },
      requested_scope: ["mcp", "offline"],
      requested_access_token_audience: [],
      context: { freshLogin },
    });

  it("GET /api/hydra/consent shows the no-passkey Approve page after a fresh login", async () => {
    seedConsent("consent-fresh-ui", true);
    const res = await testApp.app.inject({
      method: "GET",
      url: "/api/hydra/consent?consent_challenge=consent-fresh-ui",
    });
    expect(res.statusCode).toBe(200);
    expect(res.payload).toContain("/api/hydra/consent/approve");
    // No passkey ceremony on the fresh-login path.
    expect(res.payload).not.toContain("navigator.credentials");
  });

  it("GET /api/hydra/consent still requires a passkey when login was remembered", async () => {
    seedConsent("consent-stale-ui", false);
    const res = await testApp.app.inject({
      method: "GET",
      url: "/api/hydra/consent?consent_challenge=consent-stale-ui",
    });
    expect(res.statusCode).toBe(200);
    expect(res.payload).toContain("/api/hydra/consent/verify");
    expect(res.payload).toContain("navigator.credentials");
  });

  it("POST /api/hydra/consent/approve grants when login was fresh", async () => {
    seedConsent("consent-fresh-ok", true);
    const res = await testApp.app.inject({
      method: "POST",
      url: "/api/hydra/consent/approve",
      headers: { "content-type": "application/json" },
      payload: { consent_challenge: "consent-fresh-ok" },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { redirectTo?: string }).redirectTo).toContain("consent-fresh-ok");
  });

  it("POST /api/hydra/consent/approve refuses (no passkey) when login was NOT fresh", async () => {
    // Security-critical: the no-passkey path must re-check freshness against
    // Hydra's own record, so a remembered-login flow can't skip the passkey.
    seedConsent("consent-stale-deny", false);
    const res = await testApp.app.inject({
      method: "POST",
      url: "/api/hydra/consent/approve",
      headers: { "content-type": "application/json" },
      payload: { consent_challenge: "consent-stale-deny" },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("passkey_required");
  });

  it("POST /api/hydra/consent/approve returns 400 for a missing challenge", async () => {
    const res = await testApp.app.inject({
      method: "POST",
      url: "/api/hydra/consent/approve",
      headers: { "content-type": "application/json" },
      payload: {},
    });
    expect(res.statusCode).toBe(400);
  });

  // ---- Passkey revoke can optionally invalidate all sessions (#219) ----

  it("revoke with invalidateSessions terminates all of the account's Hydra sessions", async () => {
    insertCredential(testApp.conn, { label: "keep" }); // not the last active passkey
    const target = insertCredential(testApp.conn, { label: "compromised" });

    const res = await testApp.app.inject({
      method: "POST",
      url: `/api/webauthn/credentials/${target.id}/revoke`,
      headers: {
        authorization: testApp.auth,
        ...stepUpHeader(ACCOUNT_ID, STEPUP_ACTION.revokePasskey),
      },
      payload: { invalidateSessions: true },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { sessionsInvalidated: boolean }).sessionsInvalidated).toBe(true);
    // Account-wide: all consent grants (no clientId) + login sessions revoked.
    expect(testApp.hydraAdmin.revokedConsent).toContainEqual({
      subject: ACCOUNT_ID,
      clientId: undefined,
    });
    expect(testApp.hydraAdmin.revokedLogin).toContain(ACCOUNT_ID);
  });

  it("revoke without the flag leaves Hydra sessions intact", async () => {
    insertCredential(testApp.conn, { label: "keep2" });
    const target = insertCredential(testApp.conn, { label: "old" });

    const res = await testApp.app.inject({
      method: "POST",
      url: `/api/webauthn/credentials/${target.id}/revoke`,
      headers: {
        authorization: testApp.auth,
        ...stepUpHeader(ACCOUNT_ID, STEPUP_ACTION.revokePasskey),
      },
      payload: {},
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { sessionsInvalidated: boolean }).sessionsInvalidated).toBe(false);
    expect(testApp.hydraAdmin.revokedLogin).toHaveLength(0);
    expect(testApp.hydraAdmin.revokedConsent).toHaveLength(0);
  });

  // ---- Logout provider rejects unhinted (CSRF) logouts (F9) ----

  it("accepts an RP-attributed logout (valid id_token_hint → client present)", async () => {
    testApp.hydraAdmin.setLogoutRequest("logout-ok", {
      challenge: "logout-ok",
      subject: ACCOUNT_ID,
      rp_initiated: true,
      client: { client_id: "shellwatch-web" },
    });
    const res = await testApp.app.inject({
      method: "GET",
      url: "/api/hydra/logout?logout_challenge=logout-ok",
    });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toContain("post-logout");
    expect(testApp.hydraAdmin.rejectedLogout).not.toContain("logout-ok");
  });

  it("rejects an unhinted logout (no client → CSRF) without terminating the session", async () => {
    // No id_token_hint → Hydra can't attribute the logout to a client. Our
    // provider must reject rather than blindly destroy the victim's session.
    testApp.hydraAdmin.setLogoutRequest("logout-csrf", {
      challenge: "logout-csrf",
      subject: ACCOUNT_ID,
      rp_initiated: true,
      client: null,
    });
    const res = await testApp.app.inject({
      method: "GET",
      url: "/api/hydra/logout?logout_challenge=logout-csrf",
    });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe("/login");
    expect(testApp.hydraAdmin.rejectedLogout).toContain("logout-csrf");
  });
});
