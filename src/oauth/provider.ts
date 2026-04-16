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

    features: {
      devInteractions: { enabled: false },

      registration: {
        enabled: deps.config.dynamicClientRegistration !== "disabled",
        initialAccessToken: false, // anonymous DCR
        // Policies and idFactory overrides come in later PRs. Defaults are
        // spec-conformant for Phase 1.
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
          return typeof resource === "string" ? resource : "";
        },
        getResourceServerInfo: (_ctx, resource) => ({
          scope: deps.config.scopes.join(" "),
          audience: resource,
          accessTokenTTL: deps.config.accessTokenTtlSeconds,
          accessTokenFormat: "opaque",
        }),
      },

      revocation: { enabled: true },
      introspection: { enabled: false }, // in-process via adapter; no HTTP hop needed
    },
  };

  return new Provider(deps.issuer, configuration);
}
