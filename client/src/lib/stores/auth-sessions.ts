// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Account login-session management (#219). Lists the calling account's active
 * Hydra consent sessions (one per authorized client) and revokes them — single
 * or all. Both revokes require a passkey step-up. Revoking the current web UI
 * client (or all sessions) signs this browser out, so those paths end in a
 * logout/redirect.
 */
import { writable } from "svelte/store";
import { apiFetch } from "../api.js";
import { logout } from "../oauth.js";
import { performStepUp } from "./webauthn.js";

export interface AuthSession {
  clientId: string;
  clientName: string;
  scopes: string[];
  /** When consent was granted. */
  authorizedAt: string | null;
  /** When the client registered (DCR), if known. */
  createdAt: string | null;
  /** True for the web UI client — invalidating it signs you out here. */
  current: boolean;
}

export const authSessions = writable<AuthSession[]>([]);

export async function fetchAuthSessions(): Promise<void> {
  const res = await apiFetch("/api/auth/sessions");
  if (!res.ok) throw new Error("Failed to load sessions");
  const { sessions } = (await res.json()) as { sessions: AuthSession[] };
  authSessions.set(sessions);
}

/**
 * Invalidate one client's sessions for this account (its tokens die; it must
 * re-authorize). Invalidating the web UI client signs this browser out → we
 * logout/redirect; otherwise the list is refreshed.
 */
export async function revokeAuthSession(clientId: string, current: boolean): Promise<void> {
  const stepUpToken = await performStepUp("revoke_session");
  const res = await apiFetch(`/api/auth/sessions/${encodeURIComponent(clientId)}`, {
    method: "DELETE",
    headers: { "X-Shellwatch-Stepup-Token": stepUpToken },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to invalidate sessions");
  }
  if (current) {
    await logout();
    return;
  }
  await fetchAuthSessions();
}

/** Sign out everywhere (all consent + login sessions). Ends this session too. */
export async function revokeAllAuthSessions(): Promise<void> {
  const stepUpToken = await performStepUp("revoke_all_sessions");
  const res = await apiFetch("/api/auth/sessions/revoke-all", {
    method: "POST",
    headers: { "X-Shellwatch-Stepup-Token": stepUpToken },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Failed to sign out everywhere");
  }
  await logout();
}
