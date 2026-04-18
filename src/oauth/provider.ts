import Provider, { type Configuration } from "oidc-provider";
import type { ShellWatchDB } from "../db/connection.js";
import { createDrizzleAdapterFactory } from "./adapter/drizzle-adapter.js";
import type { OAuthConfig } from "./config.js";
import type { SigningKeyService } from "./signing-keys.js";

/**
 * Static client_id used by the Web UI. Tokens minted after a passkey login
 * are bound to this client. The UI never runs a redirect-based OAuth flow
 * against itself (see "Deliberate deviation" in docs/oauth-mcp.md); this
 * client entry exists because panva requires every token to be attributable
 * to a registered client.
 */
export const FIRST_PARTY_CLIENT_ID = "ui-app";

export interface OAuthProviderDeps {
  /** Absolute base URL including the `/oidc` prefix, e.g. `https://host/oidc`. */
  issuer: string;
  /** External base URL without `/oidc`, e.g. `https://host`. Used for resource-indicator substitution. */
  baseUrl: string;
  db: ShellWatchDB;
  config: OAuthConfig;
  signingKeyService: SigningKeyService;
}

/**
 * Constructs a configured panva Provider. Not mounted yet — pair with
 * `mountOAuthProvider` (see `./mount.ts`) to attach to a Fastify app.
 *
 * Centralises every panva-config decision the design doc makes so the
 * wiring layer (PR 4+) just passes the object through.
 */
export async function createOAuthProvider(deps: OAuthProviderDeps): Promise<Provider> {
  // Resolve `${baseUrl}` in configured resource indicators.
  const allowedResources = deps.config.resourceIndicators.map((r) =>
    r.replace("${baseUrl}", deps.baseUrl),
  );

  // Panva needs at least one JWK at construction. `ensureSigningKey()` must
  // have been called before us, otherwise this list is empty and panva
  // fails to boot — the wiring layer is responsible for that ordering.
  const privateJwks = await deps.signingKeyService.listActivePrivateJwks();
  if (privateJwks.length === 0) {
    throw new Error(
      "oauth: no signing keys available. Call signingKeyService.ensureSigningKey() before createOAuthProvider().",
    );
  }

  const configuration: Configuration = {
    adapter: createDrizzleAdapterFactory(deps.db),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    jwks: { keys: privateJwks as any },

    clients: [
      {
        client_id: FIRST_PARTY_CLIENT_ID,
        application_type: "web",
        // panva accepts only "implicit" or "authorization_code" in client
        // `grant_types` — refresh-token issuance is implicit when the
        // authorization_code grant is used and offline access is granted.
        grant_types: ["authorization_code"],
        response_types: ["code"],
        // Placeholder — the first-party flow never triggers a redirect.
        // Panva validates redirect_uris on code flow, so we register one
        // that can never be reached (keeps a redirect-based flow from
        // accidentally working against this client in the future).
        redirect_uris: [`${deps.issuer}/internal/first-party-no-redirect`],
        token_endpoint_auth_method: "none",
        // Our JWKS only contains Ed25519/EdDSA keys, so we must pin
        // id-token signing to EdDSA rather than panva's default RS256.
        // id_tokens aren't emitted anyway (no `openid` scope advertised)
        // but panva validates this at construction time.
        id_token_signed_response_alg: "EdDSA",
      },
    ],

    // Our JWKS is Ed25519-only. Without this default, DCR-registered
    // clients get RS256 as their id_token_signed_response_alg, and panva
    // blows up at signing time because it has no RS256 key. Setting the
    // default here means MCP clients don't need to know our key type.
    clientDefaults: {
      id_token_signed_response_alg: "EdDSA",
      // Most MCP clients register with grant_types=["authorization_code"].
      // Panva only issues refresh tokens when the client's grant_types
      // includes "refresh_token". Including it in the defaults means DCR
      // clients get refresh tokens automatically without needing to know
      // about this requirement.
      grant_types: ["authorization_code", "refresh_token"],
    },

    scopes: deps.config.scopes,

    ttl: {
      AccessToken: deps.config.accessTokenTtlSeconds,
      AuthorizationCode: deps.config.authorizationCodeTtlSeconds,
      RefreshToken: deps.config.refreshTokenTtlSeconds,
      // Sessions bound to the browser during DCR-client flows. 24h is
      // generous but bounded; the real "how long am I signed in" answer
      // lives in our sw_session / sw_refresh cookies, not here.
      Session: 60 * 60 * 24,
      // RFC 7592 registration access tokens — never expire by default in
      // panva. We leave default.
    },

    // PKCE with S256 is mandatory in OAuth 2.1; panva v9 hard-wires S256
    // as the only supported method and exposes only the `required` knob.
    pkce: {
      required: () => true,
    },

    // Stub — panva calls this when building id_tokens. We don't emit
    // id_tokens by default (no `openid` scope advertised), but
    // findAccount is still required by the config contract.
    //
    // TODO (replace before id_tokens are ever enabled): the current
    // implementation trusts any `id` panva hands us. Before advertising
    // `openid` or issuing id_tokens, this must look the account up in the
    // accounts table and reject unknown / disabled accounts. See the
    // "Account disable → token kill" open question in docs/oauth-mcp.md.
    findAccount: async (_ctx, id) => ({
      accountId: id,
      claims: async () => ({ sub: id }),
    }),

    interactions: {
      // Interaction UID lands in the URL we own; our Fastify handler
      // renders login / consent + calls back to
      // `provider.interactionFinished`. Panva puts this string into a
      // `Location` header, so it must be the full path including the
      // `/oidc` mount prefix — a root-relative URL would send the
      // browser to `/interaction/:uid` (missing prefix), 404.
      url: (_ctx, interaction) => `/oidc/interaction/${interaction.uid}`,
    },

    features: {
      devInteractions: { enabled: false },

      registration: {
        enabled: deps.config.dynamicClientRegistration !== "disabled",
        initialAccessToken: false, // anonymous DCR
      },

      // RFC 7592 management endpoint — panva requires registration to be
      // on when this is enabled, so gate on the same condition.
      registrationManagement: {
        enabled: deps.config.dynamicClientRegistration !== "disabled",
        rotateRegistrationAccessToken: false,
      },

      resourceIndicators: {
        enabled: true,
        defaultResource: (ctx) => {
          const resource = ctx.oidc.params?.resource;
          if (typeof resource === "string" && resource) return resource;
          // MCP clients (and others) that omit the `resource` parameter
          // get the first configured resource so the token carries a
          // usable audience rather than an empty one.
          return allowedResources[0] ?? "";
        },
        getResourceServerInfo: (_ctx, resource) => {
          if (!allowedResources.includes(resource)) {
            throw new Error(`oauth: unknown resource indicator "${resource}"`);
          }
          // Only include ShellWatch-defined scopes — NOT `openid`.
          // panva is an OIDC provider so it always accepts `openid`,
          // but our access tokens are pure OAuth 2.1 bearer tokens
          // consumed by /mcp and /agent-proxy, which have no use for
          // OIDC identity claims. Filtering here keeps the AT scope
          // clean; the id_token (if the client asked for openid) is
          // still issued by panva but is harmless and ignorable.
          const scope = deps.config.scopes.join(" ");
          return {
            scope,
            audience: resource,
            accessTokenTTL: deps.config.accessTokenTtlSeconds,
            accessTokenFormat: "opaque" as const,
          };
        },
      },

      revocation: { enabled: true },
      introspection: { enabled: false }, // in-process via adapter; no HTTP hop needed
    },

    // Always issue refresh tokens for authorization_code grants so
    // third-party MCP clients can renew silently. Without this, panva
    // only issues them when the `offline_access` scope is requested,
    // which most MCP clients don't send.
    issueRefreshToken: async (_ctx, client, code) => {
      if (!client.grantTypeAllowed("refresh_token")) return false;
      // code is present for authorization_code grants, undefined for
      // other grant types. Only refresh on code exchanges.
      return code !== undefined;
    },
  };

  return new Provider(deps.issuer, configuration);
}
