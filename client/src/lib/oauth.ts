// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Browser OAuth 2.1 client for the ShellWatch web UI (#217). The SPA is a
 * public PKCE client against Ory Hydra: it runs the authorization-code + PKCE
 * flow in the browser, holds the access token in memory and the (rotating)
 * refresh token in localStorage, and presents the access token as a Bearer to
 * ShellWatch's own API/WS. The login itself is gated by a passkey on
 * ShellWatch's Hydra login/consent providers.
 *
 * Bootstrap values come from window.__OAUTH__ (served by /config.js).
 */

interface OAuthBootstrap {
  issuer: string; // Hydra public issuer, e.g. http://localhost:4444
  clientId: string; // first-party public SPA client
  redirectUri: string; // ${externalUrl}/auth/callback
  scope: string; // "openid offline ui"
}

const REFRESH_TOKEN_KEY = "sw_refresh_token";
const PKCE_VERIFIER_KEY = "sw_pkce_verifier";
const OAUTH_STATE_KEY = "sw_oauth_state";
const RETURN_TO_KEY = "sw_oauth_return_to";
/** Refresh this many ms before the access token actually expires. */
const REFRESH_SKEW_MS = 30_000;

function bootstrap(): OAuthBootstrap {
  const cfg = (window as unknown as { __OAUTH__?: OAuthBootstrap }).__OAUTH__;
  if (!cfg) throw new Error("OAuth config missing (window.__OAUTH__) — is /config.js loaded?");
  return cfg;
}

// --- token state (access token in memory; refresh token in localStorage) ---
let accessToken: string | null = null;
let accessTokenExpiresAt = 0;
let refreshInFlight: Promise<string | null> | null = null;

function setRefreshToken(token: string | null): void {
  if (typeof localStorage === "undefined") return;
  if (token) localStorage.setItem(REFRESH_TOKEN_KEY, token);
  else localStorage.removeItem(REFRESH_TOKEN_KEY);
}
function getRefreshToken(): string | null {
  if (typeof localStorage === "undefined") return null;
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

// --- PKCE helpers ---
function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomB64url(nbytes: number): string {
  const a = new Uint8Array(nbytes);
  crypto.getRandomValues(a);
  return b64url(a);
}
async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(new Uint8Array(digest));
}

function storeTokens(res: {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}): void {
  accessToken = res.access_token;
  accessTokenExpiresAt = Date.now() + (res.expires_in ?? 0) * 1000;
  if (res.refresh_token) setRefreshToken(res.refresh_token);
}

/** Begin the login redirect to Hydra (→ ShellWatch passkey login/consent → callback). */
export async function beginLogin(returnTo: string): Promise<void> {
  const cfg = bootstrap();
  const verifier = randomB64url(32);
  const state = randomB64url(16);
  sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier);
  sessionStorage.setItem(OAUTH_STATE_KEY, state);
  sessionStorage.setItem(RETURN_TO_KEY, returnTo);

  const url = new URL(`${cfg.issuer}/oauth2/auth`);
  url.searchParams.set("client_id", cfg.clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", cfg.scope);
  url.searchParams.set("redirect_uri", cfg.redirectUri);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", await s256(verifier));
  url.searchParams.set("code_challenge_method", "S256");
  window.location.href = url.toString();
}

/** Handle the /auth/callback redirect: validate state, exchange the code. Returns the post-login path. */
export async function handleCallback(): Promise<string> {
  const cfg = bootstrap();
  const params = new URLSearchParams(window.location.search);
  const err = params.get("error");
  if (err) throw new Error(params.get("error_description") || err);

  const code = params.get("code");
  const state = params.get("state");
  const expectedState = sessionStorage.getItem(OAUTH_STATE_KEY);
  const verifier = sessionStorage.getItem(PKCE_VERIFIER_KEY);
  const returnTo = sessionStorage.getItem(RETURN_TO_KEY) || "/";
  sessionStorage.removeItem(OAUTH_STATE_KEY);
  sessionStorage.removeItem(PKCE_VERIFIER_KEY);
  sessionStorage.removeItem(RETURN_TO_KEY);

  if (!code || !state || !verifier) throw new Error("Invalid callback (missing code/state)");
  if (state !== expectedState) throw new Error("State mismatch — aborting (possible CSRF)");

  const res = await fetch(`${cfg.issuer}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: cfg.redirectUri,
      client_id: cfg.clientId,
      code_verifier: verifier,
    }).toString(),
  });
  if (!res.ok) throw new Error(`Token exchange failed (${res.status})`);
  storeTokens(await res.json());
  return returnTo.startsWith("/") && !returnTo.startsWith("//") ? returnTo : "/";
}

/** Exchange the stored refresh token for a fresh access token. Deduped across callers. */
async function refresh(): Promise<string | null> {
  if (refreshInFlight) return refreshInFlight;
  const rt = getRefreshToken();
  if (!rt) return null;
  const cfg = bootstrap();
  refreshInFlight = (async () => {
    try {
      const res = await fetch(`${cfg.issuer}/oauth2/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: rt,
          client_id: cfg.clientId,
        }).toString(),
      });
      if (!res.ok) {
        // Refresh token revoked/expired — session is dead.
        clearTokens();
        return null;
      }
      storeTokens(await res.json());
      return accessToken;
    } catch {
      return null;
    } finally {
      refreshInFlight = null;
    }
  })();
  return refreshInFlight;
}

/** Return a usable access token, refreshing if missing/near expiry. null if not logged in. */
export async function getAccessToken(): Promise<string | null> {
  if (accessToken && Date.now() < accessTokenExpiresAt - REFRESH_SKEW_MS) return accessToken;
  return refresh();
}

/** True if we have (or can mint) a valid access token. */
export async function isAuthenticated(): Promise<boolean> {
  return (await getAccessToken()) !== null;
}

function clearTokens(): void {
  accessToken = null;
  accessTokenExpiresAt = 0;
  setRefreshToken(null);
}

/** Revoke the refresh token at Hydra, clear local state, and go to /login. */
export async function logout(): Promise<void> {
  const cfg = bootstrap();
  const rt = getRefreshToken();
  clearTokens();
  if (rt) {
    try {
      await fetch(`${cfg.issuer}/oauth2/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: rt, client_id: cfg.clientId }).toString(),
      });
    } catch {
      // Best-effort — local tokens are already cleared.
    }
  }
  window.location.href = "/login";
}
