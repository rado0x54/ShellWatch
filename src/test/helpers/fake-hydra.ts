// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * In-memory fake of the Hydra admin/token client for tests (#217). Lets the
 * integration harness exercise the bearer gate, mediated DCR, OAuth-clients
 * route, and bearer-gate wiring without a live Hydra. Introspection is driven
 * by a registerable token map; client CRUD is a real in-memory store so the
 * oauth-clients route round-trips.
 */
import { type HydraAdminClient, HydraApiError } from "../../hydra/admin-client.js";
import type { HydraIntrospection, HydraOAuth2Client } from "../../hydra/types.js";

export interface FakeHydraAdmin extends HydraAdminClient {
  /** Register/replace what `introspect(token)` returns for a token. */
  registerToken(token: string, claims: Omit<HydraIntrospection, "active">): void;
  /** Drop a token so it introspects inactive (simulates revocation). */
  revokeRegisteredToken(token: string): void;
  /** Snapshot of created clients (by client_id). */
  clients: Map<string, HydraOAuth2Client>;
}

export function createFakeHydraAdmin(): FakeHydraAdmin {
  const tokens = new Map<string, HydraIntrospection>();
  const clients = new Map<string, HydraOAuth2Client>();
  let counter = 0;

  // Login/consent/logout challenge flows need a real Hydra redirect, so the
  // in-memory harness never drives them with a valid challenge. Model the way
  // real Hydra answers an unknown/expired challenge — a non-2xx admin response,
  // i.e. a HydraApiError — so the provider routes' guarded-admin wrapper maps it
  // to a clean 4xx instead of a 500. The 400-not-500 guard tests rely on this.
  const rejectsUnknownChallenge = (name: string) => () =>
    Promise.reject(new HydraApiError(404, "", `fake-hydra: ${name} — unknown challenge`));

  return {
    clients,
    registerToken(token, claims) {
      tokens.set(token, { active: true, ...claims });
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

    async revokeLoginSessions() {},
    async revokeConsentSessions() {},

    // See rejectsUnknownChallenge above — these reject as Hydra would for a
    // challenge it doesn't recognize.
    getLoginRequest: rejectsUnknownChallenge("getLoginRequest"),
    acceptLoginRequest: rejectsUnknownChallenge("acceptLoginRequest"),
    rejectLoginRequest: rejectsUnknownChallenge("rejectLoginRequest"),
    getConsentRequest: rejectsUnknownChallenge("getConsentRequest"),
    acceptConsentRequest: rejectsUnknownChallenge("acceptConsentRequest"),
    rejectConsentRequest: rejectsUnknownChallenge("rejectConsentRequest"),
    acceptLogoutRequest: rejectsUnknownChallenge("acceptLogoutRequest"),
  };
}
