// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Central fetch wrapper for ShellWatch's own API (#217). Attaches the OAuth
 * access token as a Bearer, transparently refreshes once on a 401, and starts
 * the OAuth flow (beginLogin) if the session is truly gone. Public/anonymous
 * endpoints (registration, passkey-status) should use bare `fetch` instead.
 */
import { beginLogin, getAccessToken, hasRefreshToken } from "./oauth.js";

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = await getAccessToken();
  const res = await doFetch(path, init, token);
  if (res.status !== 401) return res;

  // Force a real refresh + retry — covers a token the server rejected that the
  // client still considered valid (another tab rotated the grant, or a
  // transient introspection failure). Without `force`, getAccessToken() would
  // just hand back the same cached token and the retry would be a no-op.
  const fresh = await getAccessToken({ force: true });
  if (fresh && fresh !== token) {
    const retry = await doFetch(path, init, fresh);
    if (retry.status !== 401) return retry;
  }

  // Couldn't get a fresh token. If we still hold a refresh token, the failure
  // was transient (Hydra 5xx / offline — refresh() keeps the RT on those) —
  // surface the 401 and let the caller handle it rather than bouncing through a
  // login that's probably also down. Only a truly-dead session (no refresh
  // token left — revoked/expired) starts the login flow.
  if (!hasRefreshToken()) {
    await beginLogin(window.location.pathname + window.location.search);
  }
  return res;
}

function doFetch(
  path: string,
  init: RequestInit | undefined,
  token: string | null,
): Promise<Response> {
  // No token (anonymous endpoints, or before login) → pass the request through
  // untouched, preserving the original arg shape.
  if (!token) return init === undefined ? fetch(path) : fetch(path, init);
  const headers = new Headers(init?.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return fetch(path, { ...init, headers });
}
