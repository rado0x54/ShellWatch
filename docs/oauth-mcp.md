# OAuth for `/mcp`, `/agent-proxy`, and the Web UI — Design

Status: proposal
Tracking: [#107](https://github.com/rado0x54/ShellWatch/issues/107)

## Goal

Two related things, one mechanism:

1. Give MCP clients a spec-conformant way to authenticate against
   `/mcp` (and, later, `/agent-proxy`) without handing out
   pre-provisioned API keys. When a client hits `/mcp` and receives
   `401`, it should be able to run a standard OAuth 2.1 authorization
   code + PKCE flow and come back with a bearer token that ShellWatch
   accepts.
2. **Unify principal resolution.** Today the Web UI uses an
   HMAC-signed `sw_session` cookie and `/mcp` uses an API-key Bearer
   token — two parallel validation paths. After this change, the Web
   UI also carries an opaque OAuth access token (in an HttpOnly
   cookie), and _every_ request — browser, MCP, agent-proxy — is
   validated by the same `OAuthTokenVerifier`.

The MCP authorization spec
([RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) + OAuth 2.1)
explicitly allows the resource server and the authorization server to
be the same entity. That is what we do here — **ShellWatch is both**.

## Non-goals

- **No external IdP.** The passkey fleet already lives in ShellWatch.
  Federating to Google/Okta/Civic would duplicate identity state.
- **No JWT access tokens.** We want opaque, DB-backed tokens that can be
  revoked by deleting a row. JWTs move complexity (key rotation,
  revocation lists) onto us for no gain here — ShellWatch is the only
  resource server that will ever see these tokens.
- **No change to the passkey login UX.** `/login` stays WebAuthn-only.
  What changes is what happens _after_ a successful passkey verify —
  the server now mints an OAuth access + refresh token instead of
  producing an HMAC session payload.
- **No redirect-based OAuth flow for the Web UI.** The UI is a
  first-party confidential client; tokens are minted server-side
  immediately on passkey success. No code+PKCE dance against ourselves.
- **No removal of API keys.** They remain the right choice for
  headless CI agents. The API-key verifier stays in the chain
  alongside the OAuth verifier. They do move to a dedicated
  `X-API-Key` header (see above).

## Non-obvious design choices

- **Authorization server library: [`oidc-provider`](https://github.com/panva/node-oidc-provider)
  (panva).** OIDC-certified, covers discovery / PKCE / DCR / introspection /
  revocation / token rotation, and — critically — its interaction model is
  designed for "I already have a login UI, just plug it in." We do not
  write OAuth protocol code.
- **Resource-server library: none.** The RS side is ~100 lines and lets us
  keep the principal-resolution story uniform with API keys. Libraries like
  `@civic/auth-mcp` are JWT-only and come with IdP-specific defaults — a
  poor fit for opaque tokens + co-located AS.
- **Deliberate deviation from textbook OAuth for the first-party UI.**
  When AS, RS, and SPA share an origin, the canonical "SPA redirects
  to `/authorize`, AS redirects to login, AS redirects back with code,
  SPA exchanges code for tokens" flow degenerates into five
  same-origin 302s. We bypass the redirect dance: after passkey
  verify, the server mints an access + refresh token directly via
  panva's token constructors and sets HttpOnly cookies. Security
  properties are identical (passkey is the authentication step either
  way); only the HTTP choreography is simpler. This is called out
  here because a reviewer will notice it isn't in the OAuth spec.
- **API keys move to `X-API-Key`.** Today they share the
  `Authorization: Bearer` header with what will become OAuth tokens —
  two token formats on the same header is a smell that makes
  extraction brittle. Moving API keys to a dedicated `X-API-Key`
  header gives each verifier its own input source and matches
  widespread convention (OpenAI, Anthropic, Stripe-ish variants).

## Shape

```
┌────────────────────────────────────────────────────────────────────┐
│ ShellWatch                                                         │
│                                                                    │
│  ┌─────────────────────┐        ┌───────────────────────────┐      │
│  │ Passkey login       │        │ OAuth module (src/oauth)  │      │
│  │ (src/webauthn)      │        │                           │      │
│  │                     │        │ ┌───────────────────────┐ │      │
│  │ on success:         │───────►│ │ panva Provider        │ │      │
│  │   mintFirstPartyTok │  mint  │ │ opaque access tokens  │ │      │
│  └─────────┬───────────┘        │ └──────────┬────────────┘ │      │
│            │                    │            │              │      │
│            │ sets HttpOnly      │ ┌──────────┴────────────┐ │      │
│            │ sw_session=token   │ │ Drizzle adapter       │ │      │
│            ▼                    │ │ oauth_* tables        │ │      │
│  ┌─────────────────────┐        │ └──────────┬────────────┘ │      │
│  │ Browser (Web UI)    │        │            │              │      │
│  └─────────┬───────────┘        │ ┌──────────┴────────────┐ │      │
│            │ cookie             │ │ Interaction routes    │ │      │
│            │                    │ │ (DCR-client consent)  │ │      │
│  ┌─────────▼───────────┐        │ └───────────────────────┘ │      │
│  │ UI routes, WS,      │        └─────────────┬─────────────┘      │
│  │ /mcp, /agent-proxy  │                      │                    │
│  └─────────┬───────────┘                      │                    │
│            │           ┌──────────────────────┴─────────────────┐  │
│            └──────────►│ PrincipalResolver                      │  │
│                        │   apiKeyVerifier    (Bearer sw_…)      │  │
│                        │   oauthTokenVerifier (Bearer, cookie)  │  │
│                        └────────────────────┬───────────────────┘  │
│                                             │                      │
│                                  ┌──────────┴──────────┐           │
│                                  │ Principal           │           │
│                                  │  accountId, scopes, │           │
│                                  │  source, clientId?  │           │
│                                  └─────────────────────┘           │
└────────────────────────────────────────────────────────────────────┘
```

Key boundaries:

- **Every protected route** — UI, WebSocket, `/mcp`, `/agent-proxy` —
  resolves `Principal` through the same chain. No HMAC session cookie,
  no separate UI auth path.
- **Tokens for the UI and for MCP live in the same tables.** A grant is
  a grant; the only difference is whether the bearer arrives in an
  `Authorization` header or an HttpOnly cookie.
- **Passkey login code** does not import from `src/oauth`. It calls
  `mintFirstPartyToken({ accountId })`, an interface exposed by the
  OAuth module — passkey code stays OAuth-agnostic.
- **The panva adapter** is the only code that reads and writes panva's
  storage shape. Everything else goes through panva's public API or
  through `OAuthTokenVerifier`.

## Module layout

```
src/oauth/
  index.ts                  — registerOAuth(app, deps) — ONE entry point
  provider.ts               — panva Provider factory + config wiring
  verifier.ts               — OAuthTokenVerifier (implements TokenVerifier)
  first-party.ts            — mintFirstPartyToken({ accountId }) for passkey login
  cookie.ts                 — set/clear HttpOnly sw_session + sw_refresh cookies
  config.ts                 — OAuth config schema (zod) + defaults
  signing-keys.ts           — JWKS material: load / generate / rotate
  adapter/
    drizzle-adapter.ts      — panva Adapter over Drizzle (one class)
    schema.ts               — oauth_* tables (Drizzle)
  interactions/
    routes.ts               — Fastify handlers for /oidc/interaction/:uid
    login-bridge.ts         — thin bridge to src/webauthn (no OAuth logic)
    consent.ts              — consent page renderer + POST handler

src/server/auth/
  token-verifier.ts         — NEW: Principal + TokenVerifier + chain
  extract-bearer.ts         — pulls token from Authorization header OR sw_session cookie
  api-key-auth.ts           — refactored: implements TokenVerifier
  oauth-auth.ts             — wrapper that plugs OAuthTokenVerifier into the chain

src/server/app.ts           — one new call: registerOAuth(app, { db, passkey })

REMOVED:
  src/server/auth/session-cookie.ts   — HMAC session payload gone; replaced
                                         by opaque-token-in-cookie via src/oauth/cookie.ts
  src/server/auth/auth-gate.ts        — collapsed into the unified verifier chain
```

## Key abstractions

### `TokenVerifier` and `Principal` (`src/server/auth/token-verifier.ts`)

This is the shared contract that lets `/mcp` and `/agent-proxy` stay
ignorant of OAuth internals.

```ts
export type AuthSource = "api-key" | "oauth";

export interface Principal {
  accountId: string;
  scopes: string[];
  source: AuthSource;
  clientId?: string; // OAuth only — null for first-party browser tokens
  tokenId?: string; // opaque token jti (OAuth) or api_key id
  expiresAt?: Date;
}

export interface TokenVerifier {
  verify(bearer: string): Promise<Principal | null>;
}

export function chainVerifiers(
  verifiers: TokenVerifier[],
): (bearer: string) => Promise<Principal | null>;
```

### Credential presentation (`src/server/auth/extract-bearer.ts`)

The two credential types arrive on different inputs, so each verifier
reads its own source and the two paths never mix:

| Credential                               | Presented as                     |
| ---------------------------------------- | -------------------------------- |
| OAuth access token (third-party clients) | `Authorization: Bearer <opaque>` |
| OAuth access token (browser)             | `sw_session` HttpOnly cookie     |
| API key                                  | `X-API-Key: sw_<hex>`            |

```ts
export function extractOAuthBearer(req: FastifyRequest): string | null {
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) return auth.slice(7);

  const cookie = req.cookies?.sw_session;
  if (cookie) return cookie;

  return null;
}

export function extractApiKey(req: FastifyRequest): string | null {
  const header = req.headers["x-api-key"];
  return typeof header === "string" ? header : null;
}
```

Wiring (shape — not final code):

```ts
app.decorateRequest("principal", null);
app.addHook("preHandler", async (req) => {
  const apiKey = extractApiKey(req);
  if (apiKey) {
    req.principal = await apiKeyVerifier.verify(apiKey);
    if (req.principal) return;
  }

  const bearer = extractOAuthBearer(req);
  if (bearer) {
    req.principal = await oauthTokenVerifier.verify(bearer);
  }
});
```

Each verifier handles its own input; no "try-in-order-on-the-same-string"
fallback path. Cheap and unambiguous.

**Migration:** Phase 1 also accepts legacy `Authorization: Bearer sw_...`
for API keys (runs the API-key verifier on that as a last resort) so
existing `/mcp` users don't break the day OAuth ships. Phase 3 drops
the fallback, same cutover as agent-client OAuth migration.

### `OAuthTokenVerifier` (`src/oauth/verifier.ts`)

```ts
export function createOAuthTokenVerifier(
  provider: PanvaProvider,
  opts: { expectedResource: (req: FastifyRequest) => string },
): TokenVerifier;
```

Validation happens **in-process** via the adapter (no HTTP
introspection hop):

```ts
async verify(bearer) {
  const record = await provider.AccessToken.find(bearer);
  if (!record || record.isExpired) return null;

  // RFC 8707 audience binding
  if (!record.resourceIndicators?.includes(this.expectedResource)) {
    return null;
  }

  return {
    accountId: record.accountId,
    scopes: record.scopes ?? [],
    source: "oauth",
    clientId: record.clientId,
    tokenId: record.jti,
    expiresAt: new Date(record.exp * 1000),
  };
}
```

This is the only place that imports from panva outside of `src/oauth/`.
It is imported exactly once, inside `src/server/auth/oauth-auth.ts`,
and never re-exported raw — callers see the `TokenVerifier` interface.

### `401` challenge

Emitted by a **single helper** and used by both `/mcp` and
`/agent-proxy`:

```ts
function sendAuthChallenge(reply: FastifyReply) {
  const metaUrl = absoluteUrl(reply.request, "/.well-known/oauth-protected-resource");
  reply.code(401);
  reply.header("WWW-Authenticate", `Bearer realm="shellwatch", resource_metadata="${metaUrl}"`);
  reply.send({ error: "unauthorized" });
}
```

### First-party token minting (`src/oauth/first-party.ts`)

The Web UI is a first-party confidential client registered statically
in panva's config. It does not run a redirect-based OAuth flow. After
a successful passkey verify, the server directly mints tokens:

```ts
export interface FirstPartyTokenMinter {
  mint(input: { accountId: string }): Promise<{
    accessToken: string; // opaque
    accessTokenExpiresAt: Date;
    refreshToken: string; // opaque
    refreshTokenExpiresAt: Date;
  }>;
}
```

The passkey login handler calls `mint({ accountId })`, then writes two
HttpOnly cookies:

```ts
reply.setCookie("sw_session", accessToken, {
  httpOnly: true,
  secure: isHttps,
  sameSite: "strict",
  path: "/",
  expires: accessTokenExpiresAt,
});
reply.setCookie("sw_refresh", refreshToken, {
  httpOnly: true,
  secure: isHttps,
  sameSite: "strict",
  path: "/",
  expires: refreshTokenExpiresAt,
});
```

Both cookies are scoped to `path: "/"` so the server-side rolling
refresh below can rotate them on _any_ request.

### Rolling session refresh (`src/oauth/first-party.ts`)

The UI implements **no** refresh logic. Refresh happens entirely
server-side, on every request, transparent to the browser:

```
preHandler on every protected route (UI / WS / /mcp / /agent-proxy):

  1. Read sw_session cookie → oauthTokenVerifier.verify → Principal
  2. If Principal is null (expired) OR access expires within 5 min:
       - Read sw_refresh cookie
       - Ask panva to refresh → new { access, refresh }
       - Panva rotates: old refresh is consumed, a new one issued
       - setCookie(sw_session, new access)
       - setCookie(sw_refresh, new refresh)
       - Verify new access → Principal
  3. Attach req.principal, continue
```

Effect:

- User stays signed in as long as they're active — every request
  silently rolls the session forward.
- 30 days of inactivity → refresh expires → next request returns 401
  → `/login` redirect.
- Browser does nothing. No SPA interceptor, no 401-and-retry loop,
  no JS visibility into any token.

MCP clients (third-party) don't touch this path — they handle refresh
themselves against `/oidc/token` per the OAuth spec.

**Security note on broad `sw_refresh` scope.** Sending the refresh
token on every request (rather than path-scoping to a dedicated
refresh endpoint) is a deliberate trade. `HttpOnly` + `SameSite=Strict`

- `Secure` block the realistic threats: XSS can't read either cookie,
  cross-site nav can't send them. Path-scoping would add defense in
  depth at the cost of forcing the SPA into a 401-retry dance, which
  buys nothing against XSS (unreadable either way) and costs real UX.

### Login bridge (`src/oauth/interactions/login-bridge.ts`)

This is the _other_ passkey integration — for **DCR-registered
clients** (Claude Code, Cursor, VS Code) running the full code+PKCE
flow. When panva needs to authenticate a user during that flow, it
redirects to `/oidc/interaction/:uid`, and this bridge runs the passkey
ceremony inside that interaction.

```ts
export interface PasskeyLoginBridge {
  renderLogin(
    req: FastifyRequest,
    reply: FastifyReply,
    opts: {
      returnTo: string; // interaction URL to bounce back to
      prompt: "login" | "consent";
    },
  ): Promise<void>;

  completeLogin(
    req: FastifyRequest,
    reply: FastifyReply,
  ): Promise<{
    accountId: string;
  } | null>;
}
```

The handler at `/oidc/interaction/:uid`:

1. Checks for an existing `sw_session` cookie. If valid,
   `OAuthTokenVerifier` resolves it to an `accountId` → skip straight
   to consent. **No second login for an already-signed-in admin.**
2. Otherwise, renders the passkey login UI (same Svelte component as
   `/login`, different return URL).
3. On success, calls
   `provider.interactionFinished(req, reply, { login: { accountId } })`.

Both paths — first-party mint and interaction-based login — go through
`src/webauthn/` for the actual ceremony. The passkey module itself
stays OAuth-agnostic.

## Persistence

### Storage location

All new OAuth tables live in the **existing ShellWatch SQLite file**,
not a separate database. Drizzle schema goes in
`src/oauth/adapter/schema.ts` and is composed into the main Drizzle
config alongside `src/db/schema.ts`. Rationale:

- Foreign keys to `accounts` (for `oauth_grants.account_id`) only work
  within a single file.
- One migration stream, one backup, one connection pool.
- "Delete account → cascade OAuth clients and grants" is a single
  transaction.
- OAuth write volume at ShellWatch scale is a few rows/hour — no case
  for physical isolation.

If scaling pressure ever demands it, moving to Postgres splits the
schemas cleanly; no refactor needed today.

### panva adapter tables (new; owned by OAuth module)

panva defines ~10 model types. Each is stored as `(id, payload JSON,
expires_at, consumed_at?)` — the adapter is schemaless per-model:

```
oauth_clients                  — registered OAuth clients (DCR output)
oauth_authorization_codes      — short-lived, single-use (~60s)
oauth_access_tokens            — opaque bearer tokens
oauth_refresh_tokens           — long-lived, rotated on use
oauth_grants                   — user→client consent records
oauth_sessions                 — AS browser session (separate from sw_session)
oauth_interactions             — in-flight auth interactions
oauth_registration_access      — DCR registration access tokens
oauth_replay_detection         — JTI replay prevention
oauth_initial_access_tokens    — (optional) gated DCR
```

The whole adapter is one class, ~80 LOC:

```ts
export class DrizzleOidcAdapter implements PanvaAdapter {
  constructor(
    private db: DrizzleDb,
    private model: string,
  ) {}

  async upsert(id, payload, expiresIn) {
    /* INSERT OR REPLACE */
  }
  async find(id) {
    /* SELECT ... WHERE id = ? */
  }
  async findByUserCode(userCode) {
    /* device flow — unused */
  }
  async findByUid(uid) {
    /* sessions */
  }
  async consume(id) {
    /* mark consumed_at */
  }
  async destroy(id) {
    /* DELETE */
  }
  async revokeByGrantId(grantId) {
    /* DELETE WHERE grant_id = ? */
  }
}
```

### Signing keys (`src/oauth/signing-keys.ts`)

panva needs an asymmetric key pair for DCR registration access tokens
and for the `/oidc/jwks` endpoint (advertised even when access tokens
are opaque — clients still fetch it).

- Generate on first boot (RS256 / EdDSA), store in a new
  `oauth_signing_keys` table encrypted with a key derived from
  `config.security.sessionSecret`.
- Rotate every 90 days; keep the previous key active for 30 days of
  overlap.
- All of this lives inside the OAuth module — the rest of ShellWatch
  doesn't know it exists.

## End-to-end flow

Two flows live side by side: **first-party** (Web UI, no redirect
dance) and **third-party** (DCR-registered MCP clients, full code+PKCE).

### First-party Web UI login

```
1. Browser → POST /api/webauthn/login/verify
            { credential, challenge, ... }
   Server:
     - WebAuthn verify (unchanged)
     - mintFirstPartyToken({ accountId }) → { access, refresh }
     - setCookie("sw_session", access, HttpOnly; SameSite=Strict; Secure)
     - setCookie("sw_refresh", refresh, HttpOnly; path=/)
     → 200 OK

2. Browser → GET /api/endpoints    Cookie: sw_session=<opaque>
   PrincipalResolver → extractOAuthBearer (from cookie)
                    → oauthTokenVerifier.verify(<opaque>)
                    → Principal{ accountId, scopes:["mcp","agent"],
                                 source:"oauth", clientId:"ui-app" }
   Route handler sees req.principal — same shape as an MCP request.

3. Some hours later: Browser → GET /api/whatever   (access token expired)
   preHandler:
     - sw_session expired → Principal null
     - read sw_refresh cookie → panva.refresh() → new pair
     - setCookie(sw_session, new access), setCookie(sw_refresh, new refresh)
     - verify new access → Principal
   Request continues normally. Browser was never aware.

4. Browser logout → POST /api/auth/logout
   Server:
     - provider.AccessToken.destroy(access)
     - provider.RefreshToken.destroy(refresh)
     - clearCookie("sw_session"), clearCookie("sw_refresh")
```

The UI never handles bearer strings in JS. Tokens live entirely in
HttpOnly cookies. All UI routes, REST endpoints, and WebSocket upgrades
run through the same `OAuthTokenVerifier`.

### Third-party MCP client flow

Standard OAuth 2.1 authorization-code + PKCE + RFC 8707:

```
1. Client → GET /mcp                         (no token)
   ShellWatch → 401
     WWW-Authenticate: Bearer realm="shellwatch",
       resource_metadata="https://<host>/.well-known/oauth-protected-resource"

2. Client → GET /.well-known/oauth-protected-resource        (RFC 9728)
   → { resource:"https://<host>/mcp",
       authorization_servers:["https://<host>"],
       scopes_supported:["mcp","agent"],
       bearer_methods_supported:["header"] }

3. Client → GET /.well-known/oauth-authorization-server      (RFC 8414, panva)
   → { issuer, authorization_endpoint, token_endpoint,
       registration_endpoint, jwks_uri, code_challenge_methods_supported:["S256"],
       grant_types_supported:["authorization_code","refresh_token"], ... }

4. Client (no client_id) → POST /oidc/reg                    (DCR, RFC 7591)
   → { client_id, client_secret?, registration_access_token, ... }

5. Client → redirect user to /oidc/auth
            ?response_type=code
            &client_id=...
            &redirect_uri=http://127.0.0.1:PORT/callback
            &scope=mcp
            &code_challenge=...&code_challenge_method=S256
            &resource=https://<host>/mcp                     (RFC 8707)

6. panva → no session → redirects browser to
           /oidc/interaction/:uid
           ShellWatch interaction handler:
             - no sw_session     → passkey login → sw_session set
                                 → provider.interactionFinished({login:{accountId}})
             - sw_session exists → skip to consent
             - consent submitted → provider.interactionFinished({consent:{grantId}})

7. panva → 302 redirect_uri?code=...

8. Client → POST /oidc/token
            grant_type=authorization_code
            code=... code_verifier=...
            resource=https://<host>/mcp
   → { access_token: "<opaque>", refresh_token: "<opaque>",
       token_type:"Bearer", expires_in:3600, scope:"mcp" }

9. Client → GET /mcp  Authorization: Bearer <opaque>
   PrincipalResolver tries apiKeyVerifier (miss), then oauthTokenVerifier:
     provider.AccessToken.find(opaque) → record
     record.resourceIndicators includes "https://<host>/mcp"?  yes
     → Principal{ accountId, scopes:["mcp"], source:"oauth", ... }
   /mcp proceeds as normal.
```

## Configuration

Adds an `oauth` section to `config.yaml`:

```yaml
oauth:
  enabled: true

  # Scopes surfaced in metadata and accepted on /oidc/auth
  scopes: ["mcp", "agent"]

  # DCR policy:
  #   open        — anonymous DCR (matches MCP spec default, best UX)
  #   admin-only  — requires sw_session cookie on /oidc/reg
  #   disabled    — no DCR; clients must be pre-registered
  dynamicClientRegistration: open

  # Token lifetimes
  accessTokenTtlSeconds: 3600 # 1h
  refreshTokenTtlSeconds: 2592000 # 30d
  authorizationCodeTtlSeconds: 60

  # Resource indicators bound into issued tokens (RFC 8707)
  # Clients MUST pass `resource=<one of these>` on /authorize.
  resourceIndicators:
    - "${issuer}/mcp"
    - "${issuer}/agent-proxy"

  # Key rotation cadence
  signingKeyRotationDays: 90
  signingKeyOverlapDays: 30
```

Defaults are "safe and spec-conformant" — nothing needs to be set to
get a working deployment.

## DCR policy

Anonymous DCR is enabled by default (`dynamicClientRegistration: open`).
This is what makes Claude Code / Cursor / VS Code "just work" — the
user never pastes a `client_id`. The endpoint is constrained to the
minimum surface needed for MCP clients.

**Accepted on `/oidc/reg`:**

- `redirect_uris` — loopback (`http://127.0.0.1/*`, `http://localhost/*`)
  or custom scheme (`cursor://...`, `com.anthropic.claude://...`). No
  wildcards, no query strings, no fragments.
- `grant_types` ⊆ `["authorization_code", "refresh_token"]`.
- `response_types` = `["code"]`.
- `token_endpoint_auth_method` = `"none"` — public clients only; no
  client secrets are ever issued via DCR.
- `application_type` = `"native"` or omitted.

PKCE is enforced at `/oidc/auth` (panva default in OAuth 2.1 mode), not
at registration time.

**Rejected:**

- `password` or `client_credentials` grants.
- Implicit flow (`response_type=token`).
- URI schemes outside loopback / custom-scheme (no `https://`, no
  `data:`, no `file:`).
- Redirect URIs containing query strings or fragments.

**Rate limit:** 10 registrations per minute per source IP, enforced by
a Fastify hook on `/oidc/reg`. Returns `429 Too Many Requests`. Panva
does not implement this itself — we add it.

**Client lifecycle:**

- Each DCR issues a `registration_access_token` stored on the client
  record (per RFC 7591 §3).
- **No automated cleanup in Phase 1.** Panva doesn't expire Client
  records; they live until explicitly deleted. At ShellWatch scale
  (tens of rows lifetime) this is not a concern.
- Manual revocation lands in Phase 2 as a Settings UI page.
- Nightly GC (prune clients with no grants + no `/authorize` hits in
  90 days) is Phase 3, added only if the table actually becomes
  noisy.

**Expected growth:** 5–20 active clients per real user at steady state
(IDE per machine, occasional reinstalls). Not a concern at ShellWatch
scale.

**Future tightening:** flip to `admin-only` — requires `sw_session`
cookie on `/oidc/reg` — if open DCR becomes a noise source. The switch
is a middleware toggle, no table or protocol changes.

## Agent-client integration

The `agent-client/` (existing Node helper for SSH-agent forwarding over
`/agent-proxy`) gains an OAuth mode. It is not responsible for most
clients — Claude Code, VS Code, Cursor, etc. already implement the MCP
auth dance in their MCP client code. The agent-client only needs it for
standalone CLI usage.

Sketch:

```
agent-client/
  src/
    oauth/
      client.ts              — PKCE code flow, loopback listener on 127.0.0.1:0
      token-store.ts         — interface
      store-keychain.ts      — macOS Keychain (via `security` CLI or N-API)
      store-libsecret.ts     — Linux
      store-file.ts          — fallback, 0600 ~/.shellwatch/tokens.json
      refresh.ts             — opportunistic refresh at <80% TTL
    transport/
      agent-proxy-ws.ts      — on 401, runs oauth/client.ts, retries
```

## Rollout plan

1. **Phase 1 — panva mounted, unified verifier everywhere.**
   - Mount panva under `/oidc/*`; Drizzle adapter; static first-party
     `ui-app` client registered in Provider config.
   - Implement `OAuthTokenVerifier`, `extractBearer`, verifier chain.
   - Passkey login handler switches from HMAC cookie to
     `mintFirstPartyToken` + `sw_session`/`sw_refresh` cookies.
   - Delete `src/server/auth/session-cookie.ts` and `auth-gate.ts`;
     every protected route (UI, WS, `/mcp`, `/agent-proxy`) runs
     through the verifier chain.
   - DCR-client flow on `/mcp` (third-party), including
     `/oidc/interaction/:uid` passkey bridge.
   - Integration tests updated: login helpers mint tokens via the
     real flow; existing cookie-based test helpers refactored.
   - API-key verifier stays in the chain for headless clients.

2. **Phase 2 — Settings UI + DCR dedup.**
   "Authorized apps" page listing `oauth_grants` with revoke. Manual
   client revocation. Consent-page polish. UI-visible DCR policy
   switch. Deterministic `idFactory` (hash of `client_name` + first
   `redirect_uri`) so an IDE that loses local state and re-registers
   gets the same `client_id` back instead of leaving an orphan row.

3. **Phase 3 — `/agent-proxy` OAuth + agent-client support.**
   Agent-client gains an OAuth mode for standalone CLI usage.
   Keychain / libsecret / file token stores. (The server-side
   `/agent-proxy` verifier chain is already unified in Phase 1 —
   this phase is only the client-side dance.)

4. **Phase 4 (optional) — Per-endpoint scopes + nightly client GC.**
   Reuse the existing API-key endpoint-scope work.
   `mcp:endpoint:<id>` scopes surfaced in consent UI. Add nightly GC
   of stale `oauth_clients` if the table has grown enough to matter.

## Security notes

- **HTTPS enforced** outside `localhost`. panva's default; we keep it.
- **PKCE required** for all public clients (panva default in OAuth 2.1
  mode).
- **RFC 8707 resource indicator validation** — we reject tokens whose
  `aud`/`resource` doesn't match the incoming path's expected resource
  URL. Guards against cross-resource token passthrough.
- **Refresh-token rotation** — panva rotates on every use; old tokens
  are consumed (replay detection table).
- **DCR rate-limiting** — add per-IP on `/oidc/reg` even in `open`
  mode. 10/min is plenty for legitimate clients.
- **Token storage** — server-side, opaque tokens are hashed at rest in
  the adapter (panva does this by default). We never log bearer values.
- **Cookie flags** — both `sw_session` and `sw_refresh` are
  `HttpOnly`, `SameSite=Strict`, `Secure` (on HTTPS), `path=/`. No
  bearer value is ever readable from JavaScript. Refresh rotation
  happens server-side on any request (see "Rolling session refresh"),
  so the refresh cookie rides along with every request by design.
- **CSRF** — `SameSite=Strict` handles the classic cases. For
  WebSocket upgrades and non-idempotent API calls, an `Origin` header
  check is added as defense in depth.
- **Two different session concepts** — `sw_session` (our access-token
  cookie) is what authenticates API and UI calls. panva's internal AS
  session (`oauth_sessions` table) tracks "is this browser
  authenticated to the AS" during a DCR-client flow. These are not
  the same thing and must not be confused.

## Open questions

- **Account disable → token kill.** On `accounts.enabled = false`,
  outstanding OAuth tokens must stop working. Cheapest path:
  `OAuthTokenVerifier` checks `accounts.enabled` on every validate.
  Record the decision here before coding.
- **Consent-page trust signals.** With open DCR, `client_name` is
  attacker-controlled. Render it clearly labelled ("as reported by
  the client") and show the full `redirect_uri` so a vigilant user
  can spot phishing. Worth a small UX pass.
- **IP allowlist scope.** `/mcp` is allowlisted today. `/oidc/auth`
  and `/oidc/token` must stay reachable for clients to obtain tokens
  in the first place — they should _not_ be allowlisted. `/oidc/reg`
  probably should be; make it explicit in config.
- **ID tokens?** Not issued by default — MCP clients don't need them
  to call `/mcp`. Emit only if a client explicitly requests the
  `openid` scope.
- **Audit log.** Log every token issuance / revocation to
  `session_history` (or a new `auth_events` table)? Worth a small
  follow-up.
- **Mobile / PWA WebAuthn compat.** The interaction route uses the
  same component as `/login`, but the caller URL differs. Verify
  platform authenticator flows still work through the interaction
  redirect.

## References

- [MCP Authorization](https://modelcontextprotocol.io/docs/tutorials/security/authorization)
- [OAuth 2.1 draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 9728 — Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8414 — Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 7591 — Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8707 — Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)
- [`node-oidc-provider`](https://github.com/panva/node-oidc-provider) — [adapter docs](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md#adapter), [interactions docs](https://github.com/panva/node-oidc-provider/blob/main/docs/README.md#interactions)
