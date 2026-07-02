// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Coverage manifest — the single source of truth mapping every openapi.yaml
 * operationId to the golden fixture(s) that pin its wire contract, or to an
 * explicit exclusion with a stated reason. Enforced by golden-coverage.test.ts.
 *
 * Golden filenames are the `<name>` in `__goldens__/<name>.json` (no extension).
 * An operation may list several fixtures (e.g. paginated readers). Exclusions
 * must state WHY the operation is not goldened so the gap is deliberate and
 * reviewable — never silent (the #225 failure mode was an implicit ~20/54 gap).
 */

export type Coverage = { goldens: string[] } | { excluded: string };

const OPTIONS_PASSTHROUGH =
  "WebAuthn ceremony /options body is a non-deterministic @simplewebauthn passthrough " +
  "(random challenge, library-shaped); only the ShellWatch-constructed finish body is " +
  "goldened. See the golden-webauthn.test.ts docblock.";

export const GOLDEN_COVERAGE: Record<string, Coverage> = {
  // --- Meta + discovery (golden-http, golden-account) ---
  getHealth: { goldens: ["health"] },
  getVersion: { goldens: ["meta-version"] },
  getConfigScript: { goldens: ["meta-config-js"] },
  getAuthorizationServerMetadata: { goldens: ["discovery-authorization-server"] },
  getProtectedResourceMetadata: { goldens: ["discovery-protected-resource"] },
  getProtectedResourceMetadataMcp: { goldens: ["discovery-protected-resource-mcp"] },
  getProtectedResourceMetadataAgentProxy: { goldens: ["discovery-protected-resource-agent"] },

  // --- Endpoints (golden-http create/list, golden-account mutations) ---
  listEndpoints: { goldens: ["endpoints-list"] },
  createEndpoint: { goldens: ["endpoints-create"] },
  updateEndpoint: { goldens: ["endpoint-update"] },
  deleteEndpoint: { goldens: ["endpoint-delete"] },

  // --- Sessions (golden-session) ---
  createSession: { goldens: ["session-create"] },
  listSessions: { goldens: ["session-list"] },
  getSessionTail: { goldens: ["session-tail"] },
  closeSession: { goldens: ["session-close"] },

  // --- Audit (golden-audit) ---
  listAuditSessions: { goldens: ["audit-sessions-page1", "audit-sessions-page2"] },
  listAuditSignings: { goldens: ["audit-signings-page1"] },
  getAuditSigning: { goldens: ["audit-signings-by-id"] },

  // --- Current account + admin (golden-account) ---
  getCurrentAccount: { goldens: ["account-me"] },
  updateCurrentAccount: { goldens: ["account-update"] },
  listAccounts: { goldens: ["account-list"] },
  deleteAccount: { goldens: ["account-delete"] },
  exportSeedConfig: { goldens: ["account-export-seed"] },
  listSshKeys: { goldens: ["keys-list"] },

  // --- Passkey credentials + invites (golden-credentials, golden-webauthn) ---
  getPasskeyStatus: { goldens: ["passkey-status"] },
  listPasskeys: { goldens: ["credentials-list"] },
  confirmPasskey: { goldens: ["credential-confirm"] },
  updatePasskeyLabel: { goldens: ["credential-label"] },
  revokePasskey: { goldens: ["credential-revoke"] },
  createPasskeyInvite: { goldens: ["webauthn-invite-mint"] },
  getPasskeyInvite: { goldens: ["invite-get"] },
  getPasskeyInviteByToken: { goldens: ["invite-by-token"] },
  finishPasskeyRegistration: { goldens: ["webauthn-register"] },
  finishInvitePasskeyRegistration: { goldens: ["webauthn-invite-redeem"] },

  // --- Account registration + login + step-up (golden-webauthn) ---
  finishAccountRegistration: { goldens: ["webauthn-self-register"] },
  finishHydraLogin: { goldens: ["webauthn-login-verify"] },
  finishStepUp: { goldens: ["webauthn-stepup-verify"] },

  // --- WebAuthn /options passthroughs — deliberately excluded ---
  startAccountRegistration: { excluded: OPTIONS_PASSTHROUGH },
  startPasskeyRegistration: { excluded: OPTIONS_PASSTHROUGH },
  startStepUp: { excluded: OPTIONS_PASSTHROUGH },
  startHydraLogin: { excluded: OPTIONS_PASSTHROUGH },
  startInvitePasskeyRegistration: { excluded: OPTIONS_PASSTHROUGH },

  // --- Authorized clients + DCR + consent (golden-hydra) ---
  listAuthorizedClients: { goldens: ["auth-sessions-list"] },
  revokeAuthorizedClient: { goldens: ["auth-session-revoke"] },
  revokeAllAuthorizedClients: { goldens: ["auth-session-revoke-all"] },
  registerOauthClient: { goldens: ["dcr-register"] },
  approveHydraConsent: { goldens: ["consent-approve"] },
  startHydraConsent: { excluded: OPTIONS_PASSTHROUGH },
  finishHydraConsent: {
    excluded:
      "The { redirectTo } success envelope is already characterized by webauthn-login-verify " +
      "(identical accept-consent → redirect construction); the success path additionally requires " +
      "a full DB-enrolled WebAuthn assertion ceremony. Dedicated capture deferred.",
  },

  // --- Pending actions + push (golden-actions-push) ---
  getAction: { goldens: ["action-get"] },
  resolveAction: { goldens: ["action-resolve"] },
  denyAction: { goldens: ["action-deny"] },
  createPushSubscription: { goldens: ["push-subscribe"] },
  deletePushSubscription: { goldens: ["push-unsubscribe"] },
};
