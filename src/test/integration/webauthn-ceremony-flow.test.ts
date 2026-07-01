// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Ceremony-level integration tests for every WebAuthn-using endpoint (#162).
 *
 * Unlike passkey-invite-flow / passkey-stepup-flow — which stop at the gates and
 * state machines and never run the crypto — these drive the *actual* assertion
 * and attestation verification via an in-memory fake authenticator
 * (src/test/helpers/fake-authenticator.ts). They cover the happy path of:
 *
 *   - POST /api/auth/register            (self-register / bootstrap)
 *   - POST /api/hydra/login/verify       (login-provider assertion)
 *   - POST /api/webauthn/stepup/verify   (#159 step-up → token mint)
 *   - POST /api/webauthn/register        (in-account add, step-up gated)
 *   - POST /api/passkey-invite/register  (invite enrollment)
 *
 * plus the negatives that require a signer we control: counter rollback,
 * UV-required-but-not-set, origin mismatch, and RP-ID mismatch.
 *
 * The thin-app + enroll/stepUp helpers live in ../helpers/webauthn-app.ts,
 * shared with golden-webauthn.test.ts.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { webauthnCredentials } from "../../db/schema.js";
import { _resetInviteStore } from "../../webauthn/invite-store.js";
import { _resetStepUpStore, STEPUP_ACTION } from "../../webauthn/stepup-store.js";
import { createFakeAuthenticator, type FakeAuthenticator } from "../helpers/index.js";
import {
  enroll,
  injectPost as post,
  makeWebauthnApp,
  ORIGIN,
  RP_ID,
  stepUp,
  type WebauthnTestApp,
} from "../helpers/webauthn-app.js";

describe("WebAuthn ceremonies (fake authenticator)", () => {
  let c: WebauthnTestApp;

  beforeEach(async () => {
    _resetInviteStore();
    _resetStepUpStore();
    c = await makeWebauthnApp();
  });

  afterEach(() => {
    c.conn.close();
  });

  describe("happy paths", () => {
    it("POST /api/auth/register — self-register bootstrap creates an active credential", async () => {
      const optRes = await post(c.app, "/api/auth/register/options", { name: "Admin" });
      expect(optRes.statusCode).toBe(200);
      const { challenge, challengeId } = optRes.json();

      const fake = createFakeAuthenticator({ rpId: RP_ID, origin: ORIGIN });
      const res = await post(c.app, "/api/auth/register", {
        name: "Admin",
        challengeId,
        credential: fake.register(challenge),
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.verified).toBe(true);
      expect(body.accountId).toBeTruthy();

      const rows = c.conn.db.select().from(webauthnCredentials).all();
      expect(rows).toHaveLength(1);
      expect(rows[0].credentialId).toBe(fake.credentialId);
      expect(rows[0].state).toBe("active");
      // ES256 credential → OpenSSH webauthn-sk-* line is derivable from the COSE key.
      expect(rows[0].publicKeyOpenSsh).toMatch(/^webauthn-sk-ecdsa-sha2-nistp256@openssh\.com /);
    });

    it("POST /api/hydra/login/verify — assertion verifies and bumps the counter", async () => {
      const { fake, accountId } = await enroll(c.app);
      c.admin.setLoginRequest("login-chal-1");

      const optRes = await post(c.app, "/api/hydra/login/options", {});
      const { challenge, challengeId } = optRes.json();
      const res = await post(c.app, "/api/hydra/login/verify", {
        login_challenge: "login-chal-1",
        challengeId,
        credential: fake.authenticate(challenge),
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().redirectTo).toContain("login-callback");

      const row = c.conn.db.select().from(webauthnCredentials).all()[0];
      expect(row.counter).toBeGreaterThan(0); // updated from the assertion's signCount
      expect(row.lastUsedAt).toBeTruthy();
      expect(accountId).toBeTruthy();
    });

    it("POST /api/webauthn/stepup/verify — mints a usable step-up token", async () => {
      const { fake, accountId } = await enroll(c.app);
      const auth = c.bearerFor(accountId);
      const token = await stepUp(c.app, auth, fake, STEPUP_ACTION.registerPasskey);
      expect(typeof token).toBe("string");
      expect(token.length).toBeGreaterThan(0);
    });

    it("POST /api/webauthn/register — step-up-gated in-account add of a second credential", async () => {
      const { fake, accountId } = await enroll(c.app);
      const auth = c.bearerFor(accountId);
      const token = await stepUp(c.app, auth, fake, STEPUP_ACTION.registerPasskey);

      const optRes = await post(
        c.app,
        "/api/webauthn/register/options",
        { label: "Second Key" },
        { auth },
      );
      const { challenge, challengeId } = optRes.json();
      const fake2 = createFakeAuthenticator({ rpId: RP_ID, origin: ORIGIN });
      const res = await post(
        c.app,
        "/api/webauthn/register",
        { challengeId, credential: fake2.register(challenge) },
        { auth, stepUp: token },
      );

      expect(res.statusCode).toBe(200);
      expect(res.json().verified).toBe(true);
      const rows = c.conn.db.select().from(webauthnCredentials).all();
      expect(rows).toHaveLength(2);
    });

    it("POST /api/passkey-invite/register — invite enrollment adds a pending credential", async () => {
      const { accountId } = await enroll(c.app);
      const auth = c.bearerFor(accountId);

      const invRes = await post(c.app, "/api/webauthn/invite", {}, { auth });
      expect(invRes.statusCode).toBe(200);
      const token = invRes.json().invite.token;

      const optRes = await post(c.app, "/api/passkey-invite/register/options", { token });
      const { challenge, challengeId } = optRes.json();
      const fakeInv = createFakeAuthenticator({ rpId: RP_ID, origin: ORIGIN });
      const res = await post(c.app, "/api/passkey-invite/register", {
        token,
        challengeId,
        credential: fakeInv.register(challenge),
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().status).toBe("registered");
      const pending = c.conn.db
        .select()
        .from(webauthnCredentials)
        .all()
        .find((r) => r.credentialId === fakeInv.credentialId);
      expect(pending?.state).toBe("pending_confirmation");
    });
  });

  describe("negatives", () => {
    // Seed the login challenge so acceptLoginRequest would SUCCEED (→ 200) if the
    // assertion verified. This is load-bearing for the negatives: without it, an
    // unseeded challenge makes acceptLoginRequest throw → FlowError → 400, so the
    // test would pass even if UV-enforcement / origin-pinning silently regressed.
    // With it, the only path to 400 is verifyPasskeyAssertion rejecting the crypto.
    async function loginAttempt(fake: FakeAuthenticator, overrides = {}) {
      c.admin.setLoginRequest("login-chal-neg");
      const optRes = await post(c.app, "/api/hydra/login/options", {});
      const { challenge, challengeId } = optRes.json();
      return post(c.app, "/api/hydra/login/verify", {
        login_challenge: "login-chal-neg",
        challengeId,
        credential: fake.authenticate(challenge, overrides),
      });
    }

    it("rejects a counter rollback on re-authentication", async () => {
      const { fake } = await enroll(c.app);

      const first = await loginAttempt(fake, { signCount: 5 });
      expect(first.statusCode).toBe(200); // stored counter → 5

      const replay = await loginAttempt(fake, { signCount: 5 }); // not greater → rollback
      expect(replay.statusCode).toBe(400);
      expect(replay.json().error).toBeTruthy();
    });

    it("rejects an assertion without the User Verified flag", async () => {
      const { fake } = await enroll(c.app);
      const res = await loginAttempt(fake, { uv: false });
      expect(res.statusCode).toBe(400); // seeded challenge → 400 proves the crypto rejected
      expect(res.json().error).toBeTruthy();
    });

    it("rejects an origin mismatch", async () => {
      const { fake } = await enroll(c.app);
      const res = await loginAttempt(fake, { origin: "http://evil.example" });
      expect(res.statusCode).toBe(400); // seeded challenge → 400 proves the crypto rejected
      expect(res.json().error).toBeTruthy();
    });

    it("rejects an RP-ID mismatch at registration", async () => {
      const optRes = await post(c.app, "/api/auth/register/options", { name: "Admin" });
      const { challenge, challengeId } = optRes.json();
      const fake = createFakeAuthenticator({ rpId: RP_ID, origin: ORIGIN });
      const res = await post(c.app, "/api/auth/register", {
        name: "Admin",
        challengeId,
        credential: fake.register(challenge, { rpId: "evil.example" }),
      });
      expect(res.statusCode).toBe(400);
    });
  });
});
