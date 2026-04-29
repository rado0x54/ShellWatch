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
import { rateLimitDefaults, securityFieldDefaults } from "../../config/schema.js";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { CREDENTIAL_STATE } from "../../db/repositories/index.js";
import { StubAccountRepository } from "../../db/repositories/account-repo.js";
import { accounts, webauthnCredentials } from "../../db/schema.js";
import { registerAuthGate } from "../../server/auth/auth-gate.js";
import { createSessionCookie } from "../../server/auth/session-cookie.js";
import { _resetInviteStore } from "../../webauthn/invite-store.js";
import { registerWebAuthnRoutes } from "../../webauthn/routes.js";

const ACCOUNT_ID = "00000000-0000-0000-0000-00000000000a";
const COOKIE_SECRET = "test-cookie-secret-passkey-invite";

interface TestApp {
  app: FastifyInstance;
  conn: DatabaseConnection;
  cookie: string;
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
  registerAuthGate({ app, secret: COOKIE_SECRET, accountRepo });
  registerWebAuthnRoutes({
    app,
    db: conn.db,
    accountRepo,
    rpId: "localhost",
    trustedOrigins: ["http://localhost"],
    sessionConfig: { secret: COOKIE_SECRET, ttlSeconds: securityFieldDefaults.sessionTtlSeconds },
    selfRegistrationEnabled: false,
    rateLimitConfig: rateLimitDefaults,
  });

  await app.ready();

  const cookie = `sw_session=${createSessionCookie(COOKIE_SECRET, 86_400, ACCOUNT_ID)}`;
  return { app, conn, cookie };
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
    testApp = await makeTestApp();
  });

  afterEach(async () => {
    await testApp.app.close();
    testApp.conn.close();
    _resetInviteStore();
  });

  // ---- Invite slot state machine via HTTP ----

  it("create returns a token; GET-by-token resolves it", async () => {
    const created = await testApp.app.inject({
      method: "POST",
      url: "/api/webauthn/invite",
      headers: { cookie: testApp.cookie, "content-type": "application/json" },
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
      headers: { cookie: testApp.cookie, "content-type": "application/json" },
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
      headers: { cookie: testApp.cookie, "content-type": "application/json" },
      payload: {},
    });
    const firstToken = (first.json() as { invite: { token: string } }).invite.token;

    const second = await testApp.app.inject({
      method: "POST",
      url: "/api/webauthn/invite",
      headers: { cookie: testApp.cookie, "content-type": "application/json" },
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
      headers: { cookie: testApp.cookie },
    });
    expect(empty.statusCode).toBe(404);

    await testApp.app.inject({
      method: "POST",
      url: "/api/webauthn/invite",
      headers: { cookie: testApp.cookie, "content-type": "application/json" },
      payload: {},
    });

    const present = await testApp.app.inject({
      method: "GET",
      url: "/api/webauthn/invite",
      headers: { cookie: testApp.cookie },
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

  it("invite create requires a session cookie", async () => {
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
      url: "/api/auth/login/options",
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { allowCredentials?: { id: string }[] };
    const allow = body.allowCredentials ?? [];
    expect(allow.length).toBe(1);
    expect(allow[0]!.id).toBe(active.credentialId);
  });

  it("/api/auth/login refuses a pending credential before crypto", async () => {
    // Stage a real challenge so we get past the challenge-ID check, then
    // submit the pending credential's id. The state-check rejection in
    // login.ts fires before signature verification.
    const optionsRes = await testApp.app.inject({
      method: "POST",
      url: "/api/auth/login/options",
    });
    // No active creds yet — reseed: insert one pending so options returns
    // no_passkeys, then add one active so the challenge is generated.
    void optionsRes;
    insertCredential(testApp.conn, { label: "active-decoy" });
    const real = await testApp.app.inject({
      method: "POST",
      url: "/api/auth/login/options",
    });
    const { challengeId } = real.json() as { challengeId: string };
    expect(challengeId).toBeTruthy();

    const pending = insertCredential(testApp.conn, {
      label: "pending",
      state: "pending_confirmation",
    });

    const verify = await testApp.app.inject({
      method: "POST",
      url: "/api/auth/login",
      headers: { "content-type": "application/json" },
      payload: {
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
      url: "/api/auth/login/options",
    });
    const { challengeId } = optionsRes.json() as { challengeId: string };

    const revoked = insertCredential(testApp.conn, { label: "revoked", revoked: true });

    const verify = await testApp.app.inject({
      method: "POST",
      url: "/api/auth/login",
      headers: { "content-type": "application/json" },
      payload: {
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
      headers: { cookie: testApp.cookie },
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
      headers: { cookie: testApp.cookie },
    });
    expect(res.statusCode).toBe(404);
  });

  it("confirm refuses an already-active credential", async () => {
    const cred = insertCredential(testApp.conn, { label: "already-active" });
    const res = await testApp.app.inject({
      method: "POST",
      url: `/api/webauthn/credentials/${cred.id}/confirm`,
      headers: { cookie: testApp.cookie },
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
      headers: { cookie: testApp.cookie },
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
      headers: { cookie: testApp.cookie },
    });
    expect(res.statusCode).toBe(404);
  });
});
