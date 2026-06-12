// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Account login-session management (#219). Lists the calling account's active
 * Hydra consent sessions — one row per authorized OAuth client (the web UI, and
 * each MCP/agent grant) — and revokes them.
 *
 * Hydra keys sessions by subject and exposes a list only for *consent* sessions
 * (there is no per-device login-session listing), so a "session" here is an
 * authorized client, not a device. Everything is scoped to the caller's own
 * `request.accountId`; there is no cross-account access.
 *
 * Revocation is a sensitive action, so both single and bulk revoke are gated by
 * a passkey step-up (distinct actions — a single-revoke token can't be replayed
 * against revoke-all).
 */
import type { FastifyInstance } from "fastify";
import type { HydraAdminClient } from "../../hydra/admin-client.js";
import { requireStepUp } from "../../webauthn/stepup-gate.js";
import { STEPUP_ACTION } from "../../webauthn/stepup-store.js";

export interface AuthSessionRoutesParams {
  app: FastifyInstance;
  admin: HydraAdminClient;
  /** First-party SPA client id — flagged as the current ("this app") row. */
  spaClientId: string;
}

export interface AuthSessionView {
  clientId: string;
  clientName: string;
  scopes: string[];
  /** When consent was granted (Hydra handled_at). */
  authorizedAt: string | null;
  /** When the client registered (DCR), if known. */
  createdAt: string | null;
  /** True for the first-party web UI client — invalidating it signs you out here. */
  current: boolean;
}

export function registerAuthSessionRoutes(params: AuthSessionRoutesParams): void {
  const { app, admin, spaClientId } = params;

  // List the caller's authorized clients (the web UI + any MCP/agent grants).
  // Each row's action invalidates that client's *sessions* (tokens) for this
  // account — it never deletes the client, so the first-party web UI is included
  // and safe to list. Hydra can return more than one consent session per client
  // over time; collapse to one row per client_id, keeping the most recently
  // handled grant. (Distinct DCR registrations have distinct client_ids, so they
  // remain separate rows — as intended.)
  app.get("/api/auth/sessions", async (request) => {
    const sessions = await admin.listConsentSessions(request.accountId);
    const byClient = new Map<string, AuthSessionView>();
    for (const s of sessions) {
      const client = s.consent_request?.client;
      const clientId = client?.client_id;
      if (!clientId) continue;
      const handledAt = s.handled_at ?? null;
      const existing = byClient.get(clientId);
      if (existing && (existing.authorizedAt ?? "") >= (handledAt ?? "")) continue;
      byClient.set(clientId, {
        clientId,
        clientName: client.client_name || clientId,
        scopes: s.grant_scope ?? [],
        authorizedAt: handledAt,
        createdAt: client.created_at ?? null,
        current: clientId === spaClientId,
      });
    }
    // Web UI client first; the rest most-recently-authorized first.
    const list = [...byClient.values()].sort((a, b) => {
      if (a.current !== b.current) return a.current ? -1 : 1;
      return (b.authorizedAt ?? "").localeCompare(a.authorizedAt ?? "");
    });
    return { sessions: list };
  });

  // Revoke one client's grant. Revokes its consent session + associated tokens,
  // so that client (or, for the web UI, every browser using it) is signed out.
  app.delete<{ Params: { clientId: string } }>(
    "/api/auth/sessions/:clientId",
    { preHandler: requireStepUp(STEPUP_ACTION.revokeSession) },
    async (request) => {
      const { clientId } = request.params;
      await admin.revokeConsentSessions(request.accountId, clientId);
      request.log.info(
        { event: "auth_session.revoked", accountId: request.accountId, clientId },
        "auth session revoked",
      );
      return { status: "revoked" };
    },
  );

  // Sign out everywhere: revoke every consent grant AND the account's login
  // (SSO) sessions. The caller's own web session dies too — the client follows
  // up with a logout/redirect.
  app.post(
    "/api/auth/sessions/revoke-all",
    { preHandler: requireStepUp(STEPUP_ACTION.revokeAllSessions) },
    async (request) => {
      await admin.revokeConsentSessions(request.accountId);
      await admin.revokeLoginSessions(request.accountId);
      request.log.info(
        { event: "auth_session.revoked_all", accountId: request.accountId },
        "all auth sessions revoked",
      );
      return { status: "revoked_all" };
    },
  );
}
