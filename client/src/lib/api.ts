// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Central fetch wrapper for ShellWatch's own API (#217). Attaches the OAuth
 * access token as a Bearer, transparently refreshes once on a 401, and bounces
 * to /login if the session is truly gone. Public/anonymous endpoints
 * (registration, passkey-status) should use bare `fetch` instead.
 */
import { getAccessToken, beginLogin } from "./oauth.js";

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const token = await getAccessToken();
  const res = await doFetch(path, init, token);
  if (res.status !== 401) return res;

  // One forced refresh + retry — covers an access token that expired between
  // getAccessToken()'s skew check and the server's clock.
  const fresh = await getAccessToken();
  if (fresh && fresh !== token) {
    const retry = await doFetch(path, init, fresh);
    if (retry.status !== 401) return retry;
  }

  // Session is gone — start the login flow, preserving where we were.
  await beginLogin(window.location.pathname + window.location.search);
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
