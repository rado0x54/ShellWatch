// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * In-memory fake of the Hydra admin/token client for tests (#217). Lets the
 * integration harness exercise the bearer gate, mediated DCR, OAuth-clients
 * route, and bearer-gate wiring without a live Hydra. Introspection is driven
 * by a registerable token map; client CRUD is a real in-memory store so the
 * oauth-clients route round-trips.
 */
import { type HydraAdminClient, HydraApiError } from "../../hydra/admin-client.js";
import type {
  HydraConsentRequest,
  HydraConsentSession,
  HydraIntrospection,
  HydraLogoutRequest,
  HydraOAuth2Client,
} from "../../hydra/types.js";

export interface FakeHydraAdmin extends HydraAdminClient {
  /** Register/replace what `introspect(token)` returns for a token. */
  registerToken(token: string, claims: Omit<HydraIntrospection, "active">): void;
  /** Drop a token so it introspects inactive (simulates revocation). */
  revokeRegisteredToken(token: string): void;
  /** Snapshot of created clients (by client_id). */
  clients: Map<string, HydraOAuth2Client>;
  /** Seed a consent request returned by getConsentRequest (option-1 tests).
   * Once seeded, acceptConsentRequest for that challenge resolves too. */
  setConsentRequest(challenge: string, req: HydraConsentRequest): void;
  /** Seed the consent-session list returned by listConsentSessions(subject). */
  setConsentSessions(subject: string, sessions: HydraConsentSession[]): void;
  /** Seed a logout request returned by getLogoutRequest (logout-CSRF tests).
   * Once seeded, acceptLogoutRequest for that challenge resolves too. */
  setLogoutRequest(challenge: string, req: HydraLogoutRequest): void;
  /** Records of revoke calls, for assertions. */
  revokedConsent: { subject: string; clientId?: string }[];
  revokedLogin: string[];
  /** Challenges passed to rejectLogoutRequest, for assertions. */
  rejectedLogout: string[];
}

export function createFakeHydraAdmin(): FakeHydraAdmin {
  const tokens = new Map<string, HydraIntrospection>();
  const clients = new Map<string, HydraOAuth2Client>();
  const consentRequests = new Map<string, HydraConsentRequest>();
  const consentSessions = new Map<string, HydraConsentSession[]>();
  const logoutRequests = new Map<string, HydraLogoutRequest>();
  const revokedConsent: { subject: string; clientId?: string }[] = [];
  const revokedLogin: string[] = [];
  const rejectedLogout: string[] = [];
  let counter = 0;

  // Login + logout challenge flows still need a real Hydra redirect to drive
  // end-to-end, so the harness never seeds a valid challenge for them — they
  // reject the way Hydra answers an unknown/expired challenge (a non-2xx →
  // HydraApiError), which the provider routes' guarded-admin wrapper maps to a
  // clean 4xx instead of a 500 (the 400-not-500 guard tests rely on this).
  // Consent is the exception: it's seedable via setConsentRequest() so the
  // option-1 fresh-login decision is testable without a live Hydra; an unseeded
  // consent challenge still rejects the same way.
  const rejectsUnknownChallenge = (name: string) => () =>
    Promise.reject(new HydraApiError(404, "", `fake-hydra: ${name} — unknown challenge`));

  return {
    clients,
    revokedConsent,
    revokedLogin,
    rejectedLogout,
    setConsentRequest(challenge, req) {
      consentRequests.set(challenge, req);
    },
    setConsentSessions(subject, sessions) {
      consentSessions.set(subject, sessions);
    },
    setLogoutRequest(challenge, req) {
      logoutRequests.set(challenge, req);
    },
    registerToken(token, claims) {
      // Default to an access token (the gate now requires token_use=access_token);
      // callers can override via `claims`.
      tokens.set(token, { active: true, token_use: "access_token", ...claims });
    },
    revokeRegisteredToken(token) {
      tokens.delete(token);
    },

    async introspect(token) {
      return tokens.get(token) ?? { active: false };
    },

    async createClient(client) {
      counter += 1;
      const clientId = client.client_id || `hydra-client-${counter}`;
      const stored: HydraOAuth2Client = {
        ...client,
        client_id: clientId,
        client_secret: client.client_secret ?? `secret-${counter}`,
      };
      clients.set(clientId, stored);
      return stored;
    },
    async getClient(clientId) {
      return clients.get(clientId) ?? null;
    },
    async updateClient(clientId, client) {
      const stored = { ...client, client_id: clientId };
      clients.set(clientId, stored);
      return stored;
    },
    async deleteClient(clientId) {
      clients.delete(clientId);
    },

    async revokeLoginSessions(subject) {
      revokedLogin.push(subject);
    },
    async revokeConsentSessions(subject, clientId) {
      revokedConsent.push({ subject, clientId });
    },
    async listConsentSessions(subject) {
      return consentSessions.get(subject) ?? [];
    },

    // See rejectsUnknownChallenge above — these reject as Hydra would for a
    // challenge it doesn't recognize.
    getLoginRequest: rejectsUnknownChallenge("getLoginRequest"),
    acceptLoginRequest: rejectsUnknownChallenge("acceptLoginRequest"),
    rejectLoginRequest: rejectsUnknownChallenge("rejectLoginRequest"),
    // Consent: resolve seeded challenges (option-1 tests), reject others as
    // Hydra would for an unknown challenge.
    async getConsentRequest(challenge) {
      const req = consentRequests.get(challenge);
      if (!req) throw new HydraApiError(404, "", "fake-hydra: unknown consent challenge");
      return req;
    },
    async acceptConsentRequest(challenge) {
      if (!consentRequests.has(challenge)) {
        throw new HydraApiError(404, "", "fake-hydra: unknown consent challenge");
      }
      return { redirect_to: `https://hydra.test/consent-callback?c=${challenge}` };
    },
    rejectConsentRequest: rejectsUnknownChallenge("rejectConsentRequest"),
    // Logout: resolve seeded challenges (logout-CSRF tests), reject others.
    async getLogoutRequest(challenge) {
      const req = logoutRequests.get(challenge);
      if (!req) throw new HydraApiError(404, "", "fake-hydra: unknown logout challenge");
      return req;
    },
    async acceptLogoutRequest(challenge) {
      if (!logoutRequests.has(challenge)) {
        throw new HydraApiError(404, "", "fake-hydra: unknown logout challenge");
      }
      return { redirect_to: `https://hydra.test/post-logout?c=${challenge}` };
    },
    async rejectLogoutRequest(challenge) {
      rejectedLogout.push(challenge);
    },
  };
}
