// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Integration tests for the WebAuthn step-up gate on passkey management.
 *
 * What this exercises:
 *   - The HTTP gate on /api/webauthn/register, /api/webauthn/credentials/:id/
 *     revoke, and /api/webauthn/credentials/:id/confirm: missing/expired/
 *     wrong-action/wrong-account tokens are rejected with 401 + machine-
 *     readable code. (POST /api/webauthn/invite is intentionally NOT gated
 *     — see the describe block.)
 *   - The revoke happy path — a valid token + a non-last credential succeeds.
 *   - Cross-flow challenge purpose binding: a challenge minted by /stepup/
 *     options for one action can't be consumed by /stepup/verify with a
 *     different action.
 *
 * What this does NOT exercise:
 *   - The actual /api/webauthn/stepup/options + /verify ceremony beyond the
 *     challenge-purpose check (would need a fake authenticator). Tokens are
 *     minted directly via mintStepUpToken to simulate the post-assertion
 *     state for the gates.
 *   - The full register/confirm happy paths — verifyRegistrationResponse in
 *     credential-store.ts requires a real WebAuthn credential. We do verify
 *     that the token is consumed even when the inner ceremony fails.
 *
 * Built on a thin per-test Fastify app to keep the surface focused, matching
 * passkey-invite-flow.test.ts.
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
import { registerWebAuthnRoutes } from "../../webauthn/routes.js";
import { _resetInviteStore } from "../../webauthn/invite-store.js";
import { _resetStepUpStore, mintStepUpToken, STEPUP_ACTION } from "../../webauthn/stepup-store.js";

const ACCOUNT_A = "00000000-0000-0000-0000-00000000000a";
const ACCOUNT_B = "00000000-0000-0000-0000-00000000000b";
const COOKIE_SECRET = "test-cookie-secret-stepup";

interface TestApp {
  app: FastifyInstance;
  conn: DatabaseConnection;
  cookieA: string;
  cookieB: string;
}

async function makeTestApp(): Promise<TestApp> {
  const conn = createDatabase(":memory:");
  runMigrations(conn.db);

  const now = new Date().toISOString();
  conn.db
    .insert(accounts)
    .values([
      { id: ACCOUNT_A, name: "Account A", createdAt: now, updatedAt: now },
      { id: ACCOUNT_B, name: "Account B", createdAt: now, updatedAt: now },
    ])
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

  const cookieA = `sw_session=${createSessionCookie(COOKIE_SECRET, 86_400, ACCOUNT_A)}`;
  const cookieB = `sw_session=${createSessionCookie(COOKIE_SECRET, 86_400, ACCOUNT_B)}`;
  return { app, conn, cookieA, cookieB };
}

function insertCredential(
  conn: DatabaseConnection,
  opts: {
    accountId?: string;
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
      accountId: opts.accountId ?? ACCOUNT_A,
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

describe("passkey step-up gate — HTTP integration", () => {
  let testApp: TestApp;

  beforeEach(async () => {
    _resetStepUpStore();
    _resetInviteStore();
    testApp = await makeTestApp();
  });

  afterEach(async () => {
    await testApp.app.close();
    testApp.conn.close();
    _resetStepUpStore();
    _resetInviteStore();
  });

  // ---- /api/webauthn/register/options is intentionally NOT gated ----

  describe("/api/webauthn/register/options", () => {
    it("does not require a step-up token (gate lives on /register only)", async () => {
      // Need an existing credential row so excludeCredentials has something
      // to scope to (the endpoint produces a real challenge here).
      insertCredential(testApp.conn, { label: "anchor" });

      const res = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/register/options",
        headers: { cookie: testApp.cookieA, "content-type": "application/json" },
        payload: { label: "first" },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json() as { challengeId: string };
      expect(body.challengeId).toBeTruthy();
    });
  });

  // ---- /api/webauthn/register gate ----

  describe("/api/webauthn/register", () => {
    it("rejects a request without a step-up token", async () => {
      const res = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/register",
        headers: { cookie: testApp.cookieA, "content-type": "application/json" },
        payload: { challengeId: "x", credential: {} },
      });
      expect(res.statusCode).toBe(401);
      expect((res.json() as { code: string }).code).toBe("stepup_required");
    });

    it("consumes the token even when inner verification fails", async () => {
      const minted = mintStepUpToken({
        accountId: ACCOUNT_A,
        action: STEPUP_ACTION.registerPasskey,
      });
      // First call: the gate accepts, the inner challenge lookup fails (400).
      const first = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/register",
        headers: {
          cookie: testApp.cookieA,
          "content-type": "application/json",
          "x-shellwatch-stepup-token": minted.token,
        },
        payload: { challengeId: "not-a-real-challenge", credential: {} },
      });
      expect(first.statusCode).toBe(400);

      // Second call with the same token: gate rejects (token consumed).
      const second = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/register",
        headers: {
          cookie: testApp.cookieA,
          "content-type": "application/json",
          "x-shellwatch-stepup-token": minted.token,
        },
        payload: { challengeId: "not-a-real-challenge", credential: {} },
      });
      expect(second.statusCode).toBe(401);
      expect((second.json() as { code: string }).code).toBe("stepup_required");
    });
  });

  // ---- /api/webauthn/credentials/:id/revoke gate ----

  describe("/api/webauthn/credentials/:id/revoke", () => {
    it("rejects a request without a step-up token", async () => {
      const cred = insertCredential(testApp.conn, { label: "to-revoke" });
      const res = await testApp.app.inject({
        method: "POST",
        url: `/api/webauthn/credentials/${cred.id}/revoke`,
        headers: { cookie: testApp.cookieA },
      });
      expect(res.statusCode).toBe(401);
      expect((res.json() as { code: string }).code).toBe("stepup_required");
    });

    it("rejects a token minted for the register action", async () => {
      const cred = insertCredential(testApp.conn, { label: "to-revoke" });
      const minted = mintStepUpToken({
        accountId: ACCOUNT_A,
        action: STEPUP_ACTION.registerPasskey,
      });
      const res = await testApp.app.inject({
        method: "POST",
        url: `/api/webauthn/credentials/${cred.id}/revoke`,
        headers: { cookie: testApp.cookieA, "x-shellwatch-stepup-token": minted.token },
      });
      expect(res.statusCode).toBe(401);
      expect((res.json() as { code: string }).code).toBe("stepup_wrong_action");
    });

    it("rejects a token minted for a different account", async () => {
      const cred = insertCredential(testApp.conn, { label: "to-revoke" });
      const minted = mintStepUpToken({
        accountId: ACCOUNT_B,
        action: STEPUP_ACTION.revokePasskey,
      });
      const res = await testApp.app.inject({
        method: "POST",
        url: `/api/webauthn/credentials/${cred.id}/revoke`,
        headers: { cookie: testApp.cookieA, "x-shellwatch-stepup-token": minted.token },
      });
      expect(res.statusCode).toBe(401);
      expect((res.json() as { code: string }).code).toBe("stepup_wrong_account");
    });

    it("rejects token reuse — second revoke with same token fails", async () => {
      // Two active credentials so the "last active passkey" guard doesn't
      // mask the gate's behaviour on either revoke.
      const cred1 = insertCredential(testApp.conn, { label: "to-revoke-1" });
      const cred2 = insertCredential(testApp.conn, { label: "to-revoke-2" });
      // A third active credential keeps the "cannot revoke last active"
      // guard from firing on the second attempt.
      insertCredential(testApp.conn, { label: "anchor" });

      const minted = mintStepUpToken({
        accountId: ACCOUNT_A,
        action: STEPUP_ACTION.revokePasskey,
      });

      const first = await testApp.app.inject({
        method: "POST",
        url: `/api/webauthn/credentials/${cred1.id}/revoke`,
        headers: { cookie: testApp.cookieA, "x-shellwatch-stepup-token": minted.token },
      });
      expect(first.statusCode).toBe(200);
      expect((first.json() as { status: string }).status).toBe("revoked");

      const second = await testApp.app.inject({
        method: "POST",
        url: `/api/webauthn/credentials/${cred2.id}/revoke`,
        headers: { cookie: testApp.cookieA, "x-shellwatch-stepup-token": minted.token },
      });
      expect(second.statusCode).toBe(401);
      expect((second.json() as { code: string }).code).toBe("stepup_required");
    });

    it("happy path: valid token revokes the credential", async () => {
      // Need >1 active credential so the last-active guard doesn't fire.
      const cred = insertCredential(testApp.conn, { label: "to-revoke" });
      insertCredential(testApp.conn, { label: "anchor" });

      const minted = mintStepUpToken({
        accountId: ACCOUNT_A,
        action: STEPUP_ACTION.revokePasskey,
      });

      const res = await testApp.app.inject({
        method: "POST",
        url: `/api/webauthn/credentials/${cred.id}/revoke`,
        headers: { cookie: testApp.cookieA, "x-shellwatch-stepup-token": minted.token },
      });
      expect(res.statusCode).toBe(200);
      expect((res.json() as { status: string }).status).toBe("revoked");
    });

    it("step-up does NOT bypass the last-active-passkey guard", async () => {
      // Only one active credential — revoking it would lock the account
      // out. Step-up is in addition to, not a replacement for, that guard.
      const cred = insertCredential(testApp.conn, { label: "lonely" });
      const minted = mintStepUpToken({
        accountId: ACCOUNT_A,
        action: STEPUP_ACTION.revokePasskey,
      });
      const res = await testApp.app.inject({
        method: "POST",
        url: `/api/webauthn/credentials/${cred.id}/revoke`,
        headers: { cookie: testApp.cookieA, "x-shellwatch-stepup-token": minted.token },
      });
      expect(res.statusCode).toBe(400);
      expect((res.json() as { error: string }).error.toLowerCase()).toContain("last active");
    });
  });

  // ---- /api/webauthn/stepup/options sanity check ----

  describe("/api/webauthn/stepup/options", () => {
    it("requires a known action", async () => {
      const res = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/stepup/options",
        headers: { cookie: testApp.cookieA, "content-type": "application/json" },
        payload: { action: "log_in_as_root" },
      });
      expect(res.statusCode).toBe(400);
    });

    it("returns allowCredentials scoped to the caller's active credentials", async () => {
      // Caller has an active and a pending; the other account has an active.
      // Only the caller's active credential should appear.
      const callerActive = insertCredential(testApp.conn, { label: "active-A" });
      insertCredential(testApp.conn, {
        label: "pending-A",
        state: "pending_confirmation",
      });
      insertCredential(testApp.conn, {
        accountId: ACCOUNT_B,
        label: "active-B",
      });

      const res = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/stepup/options",
        headers: { cookie: testApp.cookieA, "content-type": "application/json" },
        payload: { action: STEPUP_ACTION.registerPasskey },
      });
      expect(res.statusCode).toBe(200);
      const body = res.json() as {
        allowCredentials?: { id: string }[];
        challengeId: string;
        action: string;
      };
      const ids = (body.allowCredentials ?? []).map((c) => c.id);
      expect(ids).toEqual([callerActive.credentialId]);
      expect(body.challengeId).toBeTruthy();
      expect(body.action).toBe(STEPUP_ACTION.registerPasskey);
    });

    it("400s a caller with no active credentials", async () => {
      const res = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/stepup/options",
        headers: { cookie: testApp.cookieA, "content-type": "application/json" },
        payload: { action: STEPUP_ACTION.registerPasskey },
      });
      // The endpoint returns 400 with no_active_credentials — assert the body
      // rather than relying on a fuzzy status code.
      expect(res.statusCode).toBe(400);
      expect((res.json() as { error: string }).error).toBe("no_active_credentials");
    });
  });

  // ---- /api/webauthn/invite gate ----

  describe("/api/webauthn/invite", () => {
    it("POST is NOT gated (the gate lives on confirm)", async () => {
      // Creating an invite produces a `pending_confirmation` credential
      // that's unusable until the in-account confirm step (which IS gated).
      // Asking for an assertion at both ends of the chain would force the
      // user to re-authenticate twice for one logical add.
      const res = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/invite",
        headers: { cookie: testApp.cookieA, "content-type": "application/json" },
        payload: {},
      });
      expect(res.statusCode).toBe(200);
      const body = res.json() as { invite: { token: string } };
      expect(body.invite.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    });

    it("GET /api/webauthn/invite is NOT gated (read-only)", async () => {
      // Reading the active slot doesn't change auth state. Only mutating
      // routes (POST /invite, POST /confirm, POST /revoke, POST /register)
      // need step-up.
      const res = await testApp.app.inject({
        method: "GET",
        url: "/api/webauthn/invite",
        headers: { cookie: testApp.cookieA },
      });
      // 404 = no active invite, but the gate didn't fire.
      expect(res.statusCode).toBe(404);
    });
  });

  // ---- /api/webauthn/credentials/:id/confirm gate ----

  describe("/api/webauthn/credentials/:id/confirm", () => {
    it("rejects a request without a step-up token", async () => {
      const cred = insertCredential(testApp.conn, {
        label: "to-confirm",
        state: "pending_confirmation",
      });
      const res = await testApp.app.inject({
        method: "POST",
        url: `/api/webauthn/credentials/${cred.id}/confirm`,
        headers: { cookie: testApp.cookieA },
      });
      expect(res.statusCode).toBe(401);
      expect((res.json() as { code: string }).code).toBe("stepup_required");
    });

    it("rejects a token minted for the register action", async () => {
      const cred = insertCredential(testApp.conn, {
        label: "to-confirm",
        state: "pending_confirmation",
      });
      const minted = mintStepUpToken({
        accountId: ACCOUNT_A,
        action: STEPUP_ACTION.registerPasskey,
      });
      const res = await testApp.app.inject({
        method: "POST",
        url: `/api/webauthn/credentials/${cred.id}/confirm`,
        headers: { cookie: testApp.cookieA, "x-shellwatch-stepup-token": minted.token },
      });
      expect(res.statusCode).toBe(401);
      expect((res.json() as { code: string }).code).toBe("stepup_wrong_action");
    });

    it("happy path: valid confirm_passkey token activates the credential", async () => {
      const cred = insertCredential(testApp.conn, {
        label: "to-confirm",
        state: "pending_confirmation",
      });
      const minted = mintStepUpToken({
        accountId: ACCOUNT_A,
        action: STEPUP_ACTION.confirmPasskey,
      });
      const res = await testApp.app.inject({
        method: "POST",
        url: `/api/webauthn/credentials/${cred.id}/confirm`,
        headers: { cookie: testApp.cookieA, "x-shellwatch-stepup-token": minted.token },
      });
      expect(res.statusCode).toBe(200);
      expect((res.json() as { status: string }).status).toBe("active");
    });
  });

  // ---- Cross-flow challenge purpose binding ----

  describe("challenge purpose binding", () => {
    // The threat: an XSS attacker captures the user's WebAuthn assertion
    // mid-flight (between /stepup/options and /stepup/verify) and re-targets
    // it to a different action. Without purpose binding, the same challenge
    // would surface for any action and the attacker could mint a token they
    // weren't supposed to. With binding, the consume call at /stepup/verify
    // refuses to surface a challenge stored under a different purpose.

    it("/stepup/verify rejects a register-purpose challenge presented as revoke", async () => {
      insertCredential(testApp.conn, { label: "anchor" });

      // 1. User legitimately requests step-up for register_passkey.
      const optionsRes = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/stepup/options",
        headers: { cookie: testApp.cookieA, "content-type": "application/json" },
        payload: { action: STEPUP_ACTION.registerPasskey },
      });
      expect(optionsRes.statusCode).toBe(200);
      const { challengeId } = optionsRes.json() as { challengeId: string };

      // 2. Attacker submits the same challenge with action=revoke_passkey.
      // The challenge was stored under purpose stepup:register_passkey, so
      // consumeChallenge with stepup:revoke_passkey returns null and the
      // verify endpoint reports challenge-not-found.
      const verifyRes = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/stepup/verify",
        headers: { cookie: testApp.cookieA, "content-type": "application/json" },
        payload: {
          challengeId,
          credential: { id: "x", rawId: "x", response: {}, type: "public-key" },
          action: STEPUP_ACTION.revokePasskey,
        },
      });
      expect(verifyRes.statusCode).toBe(400);
      expect((verifyRes.json() as { error: string }).error.toLowerCase()).toContain("challenge");

      // 3. The legitimate verify call with the original action also fails
      // now — the challenge was burnt by the attacker's attempt. This is
      // intentional: single-use even on purpose mismatch prevents probing.
      const legitRes = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/stepup/verify",
        headers: { cookie: testApp.cookieA, "content-type": "application/json" },
        payload: {
          challengeId,
          credential: { id: "x", rawId: "x", response: {}, type: "public-key" },
          action: STEPUP_ACTION.registerPasskey,
        },
      });
      expect(legitRes.statusCode).toBe(400);
    });

    it("/stepup/verify rejects a login-purpose challenge", async () => {
      insertCredential(testApp.conn, { label: "anchor" });

      // Mint a challenge via login/options instead of stepup/options.
      const loginOpts = await testApp.app.inject({
        method: "POST",
        url: "/api/auth/login/options",
      });
      expect(loginOpts.statusCode).toBe(200);
      const { challengeId } = loginOpts.json() as { challengeId: string };

      // Submit it to stepup/verify — should fail because the purpose doesn't
      // match (challenge was stored under "auth:login", not "stepup:*").
      const verifyRes = await testApp.app.inject({
        method: "POST",
        url: "/api/webauthn/stepup/verify",
        headers: { cookie: testApp.cookieA, "content-type": "application/json" },
        payload: {
          challengeId,
          credential: { id: "x", rawId: "x", response: {}, type: "public-key" },
          action: STEPUP_ACTION.registerPasskey,
        },
      });
      expect(verifyRes.statusCode).toBe(400);
    });
  });
});
