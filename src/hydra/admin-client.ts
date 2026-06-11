// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Thin typed client over the Ory Hydra ADMIN API (:4445). This is the single
 * chokepoint through which ShellWatch drives Hydra (#217):
 *
 *   - login/consent providers accept or reject challenges,
 *   - mediated DCR + the SPA-client bootstrap create/update clients,
 *   - the bearer gate introspects opaque access tokens,
 *   - account deletion clears the subject's Hydra login/consent sessions.
 *
 * Token exchange / refresh / revoke happen in the browser (the web UI is a
 * public PKCE client) and in the Go agent-client — never here.
 *
 * The admin API is unauthenticated by design and MUST live on a trusted
 * network only — never internet-exposed (see docs/deployment.md).
 *
 * Defined as an interface so tests can inject a fake (the real HTTP client
 * needs a live Hydra; unit/integration tests that don't exercise the protocol
 * stub it). See `createHydraAdminClient` for the production implementation.
 */
import type {
  HydraAcceptConsent,
  HydraAcceptLogin,
  HydraConsentRequest,
  HydraIntrospection,
  HydraLoginRequest,
  HydraOAuth2Client,
  HydraOAuth2ClientCreate,
  HydraRedirect,
} from "./types.js";

export interface HydraAdminClient {
  // --- Login provider ---
  getLoginRequest(challenge: string): Promise<HydraLoginRequest>;
  acceptLoginRequest(challenge: string, body: HydraAcceptLogin): Promise<HydraRedirect>;
  rejectLoginRequest(
    challenge: string,
    body: { error: string; error_description?: string },
  ): Promise<HydraRedirect>;

  // --- Consent provider ---
  getConsentRequest(challenge: string): Promise<HydraConsentRequest>;
  acceptConsentRequest(challenge: string, body: HydraAcceptConsent): Promise<HydraRedirect>;
  rejectConsentRequest(
    challenge: string,
    body: { error: string; error_description?: string },
  ): Promise<HydraRedirect>;

  // --- Client management ---
  createClient(client: HydraOAuth2ClientCreate): Promise<HydraOAuth2Client>;
  getClient(clientId: string): Promise<HydraOAuth2Client | null>;
  updateClient(clientId: string, client: HydraOAuth2Client): Promise<HydraOAuth2Client>;
  deleteClient(clientId: string): Promise<void>;

  // --- Logout provider ---
  acceptLogoutRequest(challenge: string): Promise<HydraRedirect>;

  // --- Token lifecycle ---
  /** RFC 7662 introspection — opaque access token → claims. */
  introspect(token: string): Promise<HydraIntrospection>;
  /** Delete all of a subject's Hydra login sessions (forces re-login). */
  revokeLoginSessions(subject: string): Promise<void>;
  /** Delete consent sessions for a subject (optionally scoped to one client). */
  revokeConsentSessions(subject: string, clientId?: string): Promise<void>;

  // Token exchange / refresh / revoke happen in the browser (the web UI is a
  // public PKCE client talking to Hydra's public endpoints directly) and in the
  // Go agent-client — never server-side. The admin client is admin-API only.
}

export interface CreateHydraAdminClientParams {
  /** Hydra admin base URL, e.g. http://localhost:4445 */
  adminUrl: string;
  /** Injectable for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

class HydraApiError extends Error {
  constructor(
    public status: number,
    public body: string,
    message: string,
  ) {
    super(message);
    this.name = "HydraApiError";
  }
}

export function createHydraAdminClient(params: CreateHydraAdminClientParams): HydraAdminClient {
  const { fetchImpl = fetch } = params;
  const admin = params.adminUrl.replace(/\/+$/, "");

  async function adminJson<T>(
    method: "GET" | "PUT" | "POST" | "DELETE",
    path: string,
    body?: unknown,
  ): Promise<T> {
    const res = await fetchImpl(`${admin}${path}`, {
      method,
      headers: body !== undefined ? { "content-type": "application/json" } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new HydraApiError(res.status, text, `Hydra admin ${method} ${path} → ${res.status}`);
    }
    return (text ? JSON.parse(text) : {}) as T;
  }

  return {
    getLoginRequest: (challenge) =>
      adminJson(
        "GET",
        `/admin/oauth2/auth/requests/login?login_challenge=${encodeURIComponent(challenge)}`,
      ),
    acceptLoginRequest: (challenge, body) =>
      adminJson(
        "PUT",
        `/admin/oauth2/auth/requests/login/accept?login_challenge=${encodeURIComponent(challenge)}`,
        body,
      ),
    rejectLoginRequest: (challenge, body) =>
      adminJson(
        "PUT",
        `/admin/oauth2/auth/requests/login/reject?login_challenge=${encodeURIComponent(challenge)}`,
        body,
      ),

    getConsentRequest: (challenge) =>
      adminJson(
        "GET",
        `/admin/oauth2/auth/requests/consent?consent_challenge=${encodeURIComponent(challenge)}`,
      ),
    acceptConsentRequest: (challenge, body) =>
      adminJson(
        "PUT",
        `/admin/oauth2/auth/requests/consent/accept?consent_challenge=${encodeURIComponent(challenge)}`,
        body,
      ),
    rejectConsentRequest: (challenge, body) =>
      adminJson(
        "PUT",
        `/admin/oauth2/auth/requests/consent/reject?consent_challenge=${encodeURIComponent(challenge)}`,
        body,
      ),

    createClient: (client) => adminJson("POST", "/admin/clients", client),
    getClient: async (clientId) => {
      const res = await fetchImpl(`${admin}/admin/clients/${encodeURIComponent(clientId)}`);
      if (res.status === 404) return null;
      const text = await res.text();
      if (!res.ok) {
        throw new HydraApiError(res.status, text, `Hydra admin GET client → ${res.status}`);
      }
      return JSON.parse(text) as HydraOAuth2Client;
    },
    updateClient: (clientId, client) =>
      adminJson("PUT", `/admin/clients/${encodeURIComponent(clientId)}`, client),
    deleteClient: async (clientId) => {
      const res = await fetchImpl(`${admin}/admin/clients/${encodeURIComponent(clientId)}`, {
        method: "DELETE",
      });
      if (!res.ok && res.status !== 404) {
        throw new HydraApiError(
          res.status,
          await res.text(),
          `Hydra admin DELETE client → ${res.status}`,
        );
      }
    },

    acceptLogoutRequest: (challenge) =>
      adminJson(
        "PUT",
        `/admin/oauth2/auth/requests/logout/accept?logout_challenge=${encodeURIComponent(challenge)}`,
      ),

    introspect: async (token) => {
      const res = await fetchImpl(`${admin}/admin/oauth2/introspect`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token }).toString(),
      });
      const text = await res.text();
      if (!res.ok) {
        throw new HydraApiError(res.status, text, `Hydra introspect → ${res.status}`);
      }
      return JSON.parse(text) as HydraIntrospection;
    },
    revokeLoginSessions: async (subject) => {
      const res = await fetchImpl(
        `${admin}/admin/oauth2/auth/sessions/login?subject=${encodeURIComponent(subject)}`,
        { method: "DELETE" },
      );
      if (!res.ok && res.status !== 404) {
        throw new HydraApiError(
          res.status,
          await res.text(),
          `Hydra revoke login sessions → ${res.status}`,
        );
      }
    },
    revokeConsentSessions: async (subject, clientId) => {
      const q = new URLSearchParams({ subject });
      if (clientId) q.set("client", clientId);
      else q.set("all", "true");
      const res = await fetchImpl(`${admin}/admin/oauth2/auth/sessions/consent?${q.toString()}`, {
        method: "DELETE",
      });
      if (!res.ok && res.status !== 404) {
        throw new HydraApiError(
          res.status,
          await res.text(),
          `Hydra revoke consent sessions → ${res.status}`,
        );
      }
    },
  };
}

export { HydraApiError };
