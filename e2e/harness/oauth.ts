// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Headless identity for the e2e suite (#244): the real authorization_code +
 * PKCE flow against the real Ory Hydra, with ShellWatch's passkey login and
 * consent providers driven over plain HTTP exactly as the browser would —
 * manual redirect following, a cookie jar for Hydra's CSRF/session cookies,
 * and the fake authenticator standing in for `navigator.credentials.get()`.
 *
 * Yields real Hydra-issued opaque tokens (`ui` for the web UI client, `mcp` /
 * `agent` for clients onboarded through mediated DCR) that the server under
 * test validates by introspection.
 */
import { createHash, randomBytes } from "node:crypto";
import { HYDRA_ADMIN_URL, HYDRA_PUBLIC_URL, SERVER_URL, SPA_CLIENT_ID } from "./env.js";
import type { PasskeyIdentity } from "./identity.js";

/** Minimal per-host cookie jar (Hydra sets its CSRF + session cookies on the public port). */
export class CookieJar {
  private readonly cookies = new Map<string, string>();

  absorb(url: string, res: Response): void {
    const host = new URL(url).host;
    for (const raw of res.headers.getSetCookie()) {
      const [pair, ...attrs] = raw.split(";");
      const eq = pair.indexOf("=");
      if (eq < 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = attrs.some((a) => /^\s*max-age=0\s*$/i.test(a));
      const key = `${host}|${name}`;
      if (expired || value === "") this.cookies.delete(key);
      else this.cookies.set(key, value);
    }
  }

  header(url: string): string | undefined {
    const host = new URL(url).host;
    const parts: string[] = [];
    for (const [key, value] of this.cookies) {
      const [h, name] = key.split("|");
      if (h === host) parts.push(`${name}=${value}`);
    }
    return parts.length > 0 ? parts.join("; ") : undefined;
  }
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_in?: number;
  scope?: string;
}

export interface FlowTrace {
  /** Hydra remembered the login (no passkey ceremony performed this flow). */
  loginSkipped: boolean;
  /** How consent was granted. */
  consent: "first-party" | "skip" | "approve" | "passkey" | "none";
  steps: string[];
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

async function fetchManual(url: string, jar: CookieJar, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const cookie = jar.header(url);
  if (cookie) headers.set("cookie", cookie);
  const res = await fetch(url, { ...init, headers, redirect: "manual" });
  jar.absorb(url, res);
  return res;
}

async function postJson(
  url: string,
  body: unknown,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, json: parseJsonObject(text) };
}

function parseJsonObject(text: string): Record<string, unknown> {
  if (!text) return {};
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return { raw: text };
  }
}

function locationOf(res: Response, base: string): string {
  const loc = res.headers.get("location");
  if (!loc) throw new Error(`expected a redirect from ${base}, got ${res.status} without Location`);
  return new URL(loc, base).toString();
}

export interface DriveOptions {
  identity: PasskeyIdentity;
  jar: CookieJar;
  /** The flow is finished once the browser is sent to a URL with this prefix. */
  redirectUriPrefix: string;
}

/**
 * Follow an authorize URL through Hydra ⇄ ShellWatch until the redirect back to
 * the client. Returns the final redirect URL (not fetched) and a trace of the
 * branches taken, so scenarios can assert e.g. that a remembered login forced
 * the passkey consent path.
 */
export async function driveAuthorize(
  startUrl: string,
  opts: DriveOptions,
): Promise<{ finalUrl: string; trace: FlowTrace }> {
  const { identity, jar } = opts;
  const trace: FlowTrace = { loginSkipped: false, consent: "none", steps: [] };
  let url = startUrl;

  for (let hop = 0; hop < 25; hop++) {
    if (url.startsWith(opts.redirectUriPrefix)) {
      trace.steps.push(`→ client redirect_uri`);
      return { finalUrl: url, trace };
    }
    const u = new URL(url);

    if (u.origin === HYDRA_PUBLIC_URL) {
      trace.steps.push(`GET hydra ${u.pathname}`);
      const res = await fetchManual(url, jar);
      if (res.status < 300 || res.status >= 400) {
        throw new Error(`Hydra ${u.pathname} → ${res.status}: ${(await res.text()).slice(0, 500)}`);
      }
      url = locationOf(res, url);
      continue;
    }

    if (u.origin !== SERVER_URL) throw new Error(`unexpected redirect target: ${url}`);

    if (u.pathname === "/api/hydra/error") {
      throw new Error(`Hydra sent the browser to the error page: ${u.search}`);
    }

    if (u.pathname === "/api/hydra/login") {
      const challenge = u.searchParams.get("login_challenge");
      if (!challenge) throw new Error(`login page without login_challenge: ${url}`);
      trace.steps.push("GET /api/hydra/login");
      const page = await fetchManual(url, jar);
      if (page.status >= 300 && page.status < 400) {
        // Remembered session: the provider accepted without a ceremony.
        trace.loginSkipped = true;
        trace.steps.push("login skipped (remembered)");
        url = locationOf(page, url);
        continue;
      }
      if (page.status !== 200) {
        throw new Error(`login page → ${page.status}: ${(await page.text()).slice(0, 300)}`);
      }
      const options = await postJson(`${SERVER_URL}/api/hydra/login/options`, {});
      if (options.status !== 200 || typeof options.json.challenge !== "string") {
        throw new Error(`login/options → ${options.status} ${JSON.stringify(options.json)}`);
      }
      const credential = identity.fake.authenticate(options.json.challenge as string);
      const verify = await postJson(`${SERVER_URL}/api/hydra/login/verify`, {
        login_challenge: challenge,
        challengeId: options.json.challengeId,
        credential,
      });
      if (verify.status !== 200 || typeof verify.json.redirectTo !== "string") {
        throw new Error(`login/verify → ${verify.status} ${JSON.stringify(verify.json)}`);
      }
      trace.steps.push("passkey login verified");
      url = verify.json.redirectTo as string;
      continue;
    }

    if (u.pathname === "/api/hydra/consent") {
      const challenge = u.searchParams.get("consent_challenge");
      if (!challenge) throw new Error(`consent page without consent_challenge: ${url}`);
      trace.steps.push("GET /api/hydra/consent");
      const page = await fetchManual(url, jar);
      if (page.status >= 300 && page.status < 400) {
        trace.consent = trace.consent === "none" ? "first-party" : trace.consent;
        trace.steps.push("consent auto-accepted (first-party or remembered)");
        url = locationOf(page, url);
        continue;
      }
      if (page.status !== 200) {
        throw new Error(`consent page → ${page.status}: ${(await page.text()).slice(0, 300)}`);
      }
      // Fresh passkey login in this very flow → plain Approve; otherwise the
      // provider demands a passkey (option-1 in src/hydra/routes.ts).
      const approve = await postJson(`${SERVER_URL}/api/hydra/consent/approve`, {
        consent_challenge: challenge,
      });
      if (approve.status === 200 && typeof approve.json.redirectTo === "string") {
        trace.consent = "approve";
        trace.steps.push("consent approved (fresh login, no passkey)");
        url = approve.json.redirectTo as string;
        continue;
      }
      if (approve.status !== 400 || approve.json.error !== "passkey_required") {
        throw new Error(`consent/approve → ${approve.status} ${JSON.stringify(approve.json)}`);
      }
      const options = await postJson(`${SERVER_URL}/api/hydra/consent/options`, {
        consent_challenge: challenge,
      });
      if (options.status !== 200 || typeof options.json.challenge !== "string") {
        throw new Error(`consent/options → ${options.status} ${JSON.stringify(options.json)}`);
      }
      const verify = await postJson(`${SERVER_URL}/api/hydra/consent/verify`, {
        consent_challenge: challenge,
        challengeId: options.json.challengeId,
        credential: identity.fake.authenticate(options.json.challenge as string),
      });
      if (verify.status !== 200 || typeof verify.json.redirectTo !== "string") {
        throw new Error(`consent/verify → ${verify.status} ${JSON.stringify(verify.json)}`);
      }
      trace.consent = "passkey";
      trace.steps.push("consent approved with passkey (remembered login)");
      url = verify.json.redirectTo as string;
      continue;
    }

    throw new Error(`unexpected ShellWatch redirect target: ${url}`);
  }
  throw new Error(`authorize flow did not terminate within 25 hops (last: ${url})`);
}

export interface AuthorizeParams {
  clientId: string;
  redirectUri: string;
  scope: string;
  identity: PasskeyIdentity;
  /** Reuse a jar to simulate the same browser (remembered Hydra login). */
  jar?: CookieJar;
}

export async function authorizationCode(
  p: AuthorizeParams,
): Promise<{ code: string; verifier: string; jar: CookieJar; trace: FlowTrace }> {
  const jar = p.jar ?? new CookieJar();
  const { verifier, challenge } = pkcePair();
  const state = randomBytes(12).toString("base64url");
  const qs = new URLSearchParams({
    response_type: "code",
    client_id: p.clientId,
    redirect_uri: p.redirectUri,
    scope: p.scope,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  const { finalUrl, trace } = await driveAuthorize(`${HYDRA_PUBLIC_URL}/oauth2/auth?${qs}`, {
    identity: p.identity,
    jar,
    redirectUriPrefix: p.redirectUri,
  });
  const cb = new URL(finalUrl);
  if (cb.searchParams.get("error")) {
    throw new Error(
      `authorize failed: ${cb.searchParams.get("error")} — ${cb.searchParams.get("error_description")}`,
    );
  }
  if (cb.searchParams.get("state") !== state) throw new Error("state mismatch on callback");
  const code = cb.searchParams.get("code");
  if (!code) throw new Error(`callback without code: ${finalUrl}`);
  return { code, verifier, jar, trace };
}

async function tokenRequest(form: Record<string, string>): Promise<TokenResponse> {
  const res = await fetch(`${HYDRA_PUBLIC_URL}/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  });
  const text = await res.text();
  if (!res.ok) {
    const err = new Error(`token endpoint → ${res.status}: ${text}`) as Error & {
      status: number;
      body: string;
    };
    err.status = res.status;
    err.body = text;
    throw err;
  }
  return JSON.parse(text) as TokenResponse;
}

export function exchangeCode(p: {
  clientId: string;
  code: string;
  verifier: string;
  redirectUri: string;
}): Promise<TokenResponse> {
  return tokenRequest({
    grant_type: "authorization_code",
    code: p.code,
    redirect_uri: p.redirectUri,
    code_verifier: p.verifier,
    client_id: p.clientId,
  });
}

export function refreshTokens(clientId: string, refreshToken: string): Promise<TokenResponse> {
  return tokenRequest({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: clientId,
  });
}

/** RFC 7009 revocation at Hydra's public endpoint (public client → client_id only). */
export async function revokeToken(clientId: string, token: string): Promise<number> {
  const res = await fetch(`${HYDRA_PUBLIC_URL}/oauth2/revoke`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token, client_id: clientId }).toString(),
  });
  await res.text();
  return res.status;
}

/** RFC 7662 introspection straight at Hydra's admin API (what the server's bearer gate calls). */
export async function introspect(
  token: string,
): Promise<{ active: boolean; sub?: string; scope?: string; client_id?: string }> {
  const res = await fetch(`${HYDRA_ADMIN_URL}/admin/oauth2/introspect`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token }).toString(),
  });
  if (!res.ok) throw new Error(`introspect → ${res.status}: ${await res.text()}`);
  return (await res.json()) as {
    active: boolean;
    sub?: string;
    scope?: string;
    client_id?: string;
  };
}

export async function hydraOpenIdConfiguration(): Promise<Record<string, unknown>> {
  const res = await fetch(`${HYDRA_PUBLIC_URL}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`Hydra discovery → ${res.status}`);
  return (await res.json()) as Record<string, unknown>;
}

export const SPA_REDIRECT_URI = `${SERVER_URL}/auth/callback`;
export const UI_SCOPE = "openid offline_access ui";

/** Sign in as the web UI would (first-party SPA client, auto-consent). */
export async function loginWebUi(
  identity: PasskeyIdentity,
  jar?: CookieJar,
): Promise<{ tokens: TokenResponse; trace: FlowTrace; jar: CookieJar }> {
  const auth = await authorizationCode({
    clientId: SPA_CLIENT_ID,
    redirectUri: SPA_REDIRECT_URI,
    scope: UI_SCOPE,
    identity,
    jar,
  });
  const tokens = await exchangeCode({
    clientId: SPA_CLIENT_ID,
    code: auth.code,
    verifier: auth.verifier,
    redirectUri: SPA_REDIRECT_URI,
  });
  return { tokens, trace: auth.trace, jar: auth.jar };
}

export interface DcrResponse {
  client_id: string;
  scope: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  client_name: string;
  client_id_issued_at: number;
}

/** Mediated DCR — what an MCP client or shellwatch-agent does before its first login. */
export async function registerClient(p: {
  clientName: string;
  redirectUri: string;
  scope: "mcp" | "agent";
}): Promise<DcrResponse> {
  const { status, json } = await postJson(`${SERVER_URL}/api/hydra/register`, {
    client_name: p.clientName,
    redirect_uris: [p.redirectUri],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    scope: p.scope,
    token_endpoint_auth_method: "none",
  });
  if (status !== 201) throw new Error(`DCR → ${status}: ${JSON.stringify(json)}`);
  return json as unknown as DcrResponse;
}

/** Onboard a third-party client end-to-end: DCR → passkey login → consent → tokens. */
export async function loginThirdPartyClient(p: {
  clientName: string;
  scope: "mcp" | "agent";
  identity: PasskeyIdentity;
  jar?: CookieJar;
  /** Loopback redirect, as MCP clients / the agent register. Default: a fixed loopback port. */
  redirectUri?: string;
}): Promise<{
  tokens: TokenResponse;
  clientId: string;
  redirectUri: string;
  trace: FlowTrace;
  jar: CookieJar;
}> {
  const redirectUri =
    p.redirectUri ?? `http://127.0.0.1:${40000 + Math.floor(Math.random() * 20000)}/callback`;
  const dcr = await registerClient({ clientName: p.clientName, redirectUri, scope: p.scope });
  const scope = `${p.scope} offline_access`;
  const auth = await authorizationCode({
    clientId: dcr.client_id,
    redirectUri,
    scope,
    identity: p.identity,
    jar: p.jar,
  });
  const tokens = await exchangeCode({
    clientId: dcr.client_id,
    code: auth.code,
    verifier: auth.verifier,
    redirectUri,
  });
  return { tokens, clientId: dcr.client_id, redirectUri, trace: auth.trace, jar: auth.jar };
}

/** Mint a step-up token (sensitive actions) with the fake authenticator. */
export async function stepUpToken(
  uiToken: string,
  identity: PasskeyIdentity,
  action: string,
): Promise<string> {
  const headers = { "content-type": "application/json", authorization: `Bearer ${uiToken}` };
  const optRes = await fetch(`${SERVER_URL}/api/webauthn/stepup/options`, {
    method: "POST",
    headers,
    body: JSON.stringify({ action }),
  });
  const opt = (await optRes.json()) as { challenge: string; challengeId: string; error?: string };
  if (optRes.status !== 200)
    throw new Error(`stepup/options → ${optRes.status} ${JSON.stringify(opt)}`);
  const verRes = await fetch(`${SERVER_URL}/api/webauthn/stepup/verify`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      challengeId: opt.challengeId,
      credential: identity.fake.authenticate(opt.challenge),
      action,
    }),
  });
  const ver = (await verRes.json()) as { stepUpToken: string; error?: string };
  if (verRes.status !== 200)
    throw new Error(`stepup/verify → ${verRes.status} ${JSON.stringify(ver)}`);
  return ver.stepUpToken;
}

/** Create a second account through the anonymous self-registration ceremony. */
export async function selfRegister(
  identity: PasskeyIdentity,
  name: string,
): Promise<{ accountId: string }> {
  const opt = await postJson(`${SERVER_URL}/api/auth/register/options`, { name });
  if (opt.status !== 200)
    throw new Error(`register/options → ${opt.status} ${JSON.stringify(opt.json)}`);
  const reg = await postJson(`${SERVER_URL}/api/auth/register`, {
    name,
    challengeId: opt.json.challengeId,
    credential: identity.fake.register(opt.json.challenge as string),
  });
  if (reg.status !== 200) throw new Error(`register → ${reg.status} ${JSON.stringify(reg.json)}`);
  return { accountId: reg.json.accountId as string };
}
