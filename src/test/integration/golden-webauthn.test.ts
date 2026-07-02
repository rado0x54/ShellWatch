// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden characterization of the WebAuthn ceremony *response envelopes* — the
 * ShellWatch-owned bodies returned once the crypto verifies (self-register,
 * login-provider, step-up, in-account register, invite mint + redeem). Parity
 * oracle for the Go rewrite (#225); unblocked by the fake authenticator (#162).
 *
 * The `/options` bodies are @simplewebauthn passthroughs (documented loosely in
 * openapi.yaml) and are NOT goldened here — this suite pins the response shapes
 * ShellWatch itself constructs. Determinism comes from a fixed keypair +
 * credential id (so credentialId / OpenSSH line / fingerprint are stable); the
 * remaining volatile fields fold via the standard normalizer (challenge/token →
 * <REDACTED>, timestamps → <TS>, account/credential-row UUIDs → <UUID>).
 */
import { afterEach, beforeEach, describe, it } from "vitest";
import { _resetInviteStore } from "../../webauthn/invite-store.js";
import { _resetStepUpStore, STEPUP_ACTION } from "../../webauthn/stepup-store.js";
import { createFakeAuthenticator, expectGolden } from "../helpers/index.js";
import {
  enroll,
  injectPost as post,
  makeWebauthnApp,
  ORIGIN,
  RP_ID,
  stepUp,
  type WebauthnTestApp,
} from "../helpers/webauthn-app.js";

// Two fixed PKCS#8 P-256 keys + credential ids → deterministic derived material.
// KEY_A is the bootstrap credential; KEY_B is any "second" credential in the
// same account (distinct credentialId to satisfy the UNIQUE constraint).
const KEY_A = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFURdtKNp9vRrua9H
IL7BU5NAx1YUksvk3FMc4JRf60ChRANCAAQvpMYo+35LLiFuv8Mb/+E+SiM2o/fc
iCMQdix5EHFumzvyz+r9NDP8PfipOfiKWj+hObIDlm3B3Tgg9pSL0Jw+
-----END PRIVATE KEY-----`;
const KEY_B = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1rHReRT2jK70bmfr
/HQzcdjkbhuyTAnoSpQIELuPWHqhRANCAARb2s6SmuPtCSbGFCL3IqBATU34YZDP
H9HP58YGEmKIAykoTUreRRPdkD8Ycc7QBehkLxk8wIVGJFr1A/2KWiWH
-----END PRIVATE KEY-----`;
const CRED_A = new Uint8Array(32).fill(0x0a);
const CRED_B = new Uint8Array(32).fill(0x0b);

const fakeA = () =>
  createFakeAuthenticator({
    rpId: RP_ID,
    origin: ORIGIN,
    privateKeyPem: KEY_A,
    credentialId: CRED_A,
  });
const fakeB = () =>
  createFakeAuthenticator({
    rpId: RP_ID,
    origin: ORIGIN,
    privateKeyPem: KEY_B,
    credentialId: CRED_B,
  });

function snap(name: string, res: { statusCode: number; json: () => unknown }) {
  expectGolden(import.meta.url, name, { status: res.statusCode, body: res.json() });
}

describe("Golden: WebAuthn ceremony responses", () => {
  let c: WebauthnTestApp;

  beforeEach(async () => {
    _resetInviteStore();
    _resetStepUpStore();
    c = await makeWebauthnApp();
  });

  afterEach(() => {
    c.conn.close();
  });

  it("POST /api/auth/register (self-register)", async () => {
    const optRes = await post(c.app, "/api/auth/register/options", { name: "User" });
    const { challenge, challengeId } = optRes.json();
    const res = await post(c.app, "/api/auth/register", {
      name: "User",
      challengeId,
      credential: fakeA().register(challenge),
    });
    snap("webauthn-self-register", res);
  });

  it("POST /api/hydra/login/verify", async () => {
    const { fake } = await enroll(c.app, fakeA());
    c.admin.setLoginRequest("login-chal-1");
    const optRes = await post(c.app, "/api/hydra/login/options", {});
    const { challenge, challengeId } = optRes.json();
    const res = await post(c.app, "/api/hydra/login/verify", {
      login_challenge: "login-chal-1",
      challengeId,
      credential: fake.authenticate(challenge),
    });
    snap("webauthn-login-verify", res);
  });

  it("POST /api/webauthn/stepup/verify", async () => {
    const { fake, accountId } = await enroll(c.app, fakeA());
    const auth = c.bearerFor(accountId);
    const optRes = await post(
      c.app,
      "/api/webauthn/stepup/options",
      { action: STEPUP_ACTION.registerPasskey },
      { auth },
    );
    const { challenge, challengeId } = optRes.json();
    const res = await post(
      c.app,
      "/api/webauthn/stepup/verify",
      {
        challengeId,
        credential: fake.authenticate(challenge),
        action: STEPUP_ACTION.registerPasskey,
      },
      { auth },
    );
    snap("webauthn-stepup-verify", res);
  });

  it("POST /api/webauthn/register (in-account add)", async () => {
    const { fake, accountId } = await enroll(c.app, fakeA());
    const auth = c.bearerFor(accountId);
    const token = await stepUp(c.app, auth, fake, STEPUP_ACTION.registerPasskey);
    const optRes = await post(
      c.app,
      "/api/webauthn/register/options",
      { label: "Second Key" },
      { auth },
    );
    const { challenge, challengeId } = optRes.json();
    const res = await post(
      c.app,
      "/api/webauthn/register",
      { challengeId, credential: fakeB().register(challenge) },
      { auth, stepUp: token },
    );
    snap("webauthn-register", res);
  });

  it("POST /api/webauthn/invite (mint) + /api/passkey-invite/register (redeem)", async () => {
    const { accountId } = await enroll(c.app, fakeA());
    const auth = c.bearerFor(accountId);

    const mintRes = await post(c.app, "/api/webauthn/invite", {}, { auth });
    snap("webauthn-invite-mint", mintRes);
    const token = mintRes.json().invite.token;

    const optRes = await post(c.app, "/api/passkey-invite/register/options", { token });
    const { challenge, challengeId } = optRes.json();
    const res = await post(c.app, "/api/passkey-invite/register", {
      token,
      challengeId,
      credential: fakeB().register(challenge),
    });
    snap("webauthn-invite-redeem", res);
  });
});
