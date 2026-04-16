import { index, sqliteTable, text } from "drizzle-orm/sqlite-core";

/**
 * Shared column layout for every panva model. panva's Adapter interface is
 * uniform across models — each one is effectively a (id, payload, TTL,
 * lookup-by-alt-keys) row. Keeping the shape identical per table lets the
 * Drizzle adapter be one class parameterised by table reference.
 */
const panvaModelCols = {
  id: text("id").primaryKey(),
  payload: text("payload", { mode: "json" }).notNull(),
  grantId: text("grant_id"),
  userCode: text("user_code"),
  uid: text("uid"),
  consumedAt: text("consumed_at"),
  expiresAt: text("expires_at"),
  createdAt: text("created_at").notNull(),
} as const;

// ----- panva model tables -----

export const oauthSessions = sqliteTable("oauth_sessions", panvaModelCols, (t) => [
  index("oauth_sessions_grant_id_idx").on(t.grantId),
  index("oauth_sessions_uid_idx").on(t.uid),
  index("oauth_sessions_expires_at_idx").on(t.expiresAt),
]);

export const oauthAccessTokens = sqliteTable("oauth_access_tokens", panvaModelCols, (t) => [
  index("oauth_access_tokens_grant_id_idx").on(t.grantId),
  index("oauth_access_tokens_expires_at_idx").on(t.expiresAt),
]);

export const oauthAuthorizationCodes = sqliteTable(
  "oauth_authorization_codes",
  panvaModelCols,
  (t) => [
    index("oauth_authorization_codes_grant_id_idx").on(t.grantId),
    index("oauth_authorization_codes_expires_at_idx").on(t.expiresAt),
  ],
);

export const oauthRefreshTokens = sqliteTable("oauth_refresh_tokens", panvaModelCols, (t) => [
  index("oauth_refresh_tokens_grant_id_idx").on(t.grantId),
  index("oauth_refresh_tokens_expires_at_idx").on(t.expiresAt),
]);

export const oauthDeviceCodes = sqliteTable("oauth_device_codes", panvaModelCols, (t) => [
  index("oauth_device_codes_user_code_idx").on(t.userCode),
  index("oauth_device_codes_grant_id_idx").on(t.grantId),
  index("oauth_device_codes_expires_at_idx").on(t.expiresAt),
]);

export const oauthClientCredentials = sqliteTable(
  "oauth_client_credentials",
  panvaModelCols,
  (t) => [index("oauth_client_credentials_expires_at_idx").on(t.expiresAt)],
);

// Dynamic (DCR-registered) clients. `expires_at` is always NULL on this
// model — registered clients live until explicitly deleted — so no TTL
// index is declared.
export const oauthClients = sqliteTable("oauth_clients", panvaModelCols);

export const oauthInitialAccessTokens = sqliteTable(
  "oauth_initial_access_tokens",
  panvaModelCols,
  (t) => [index("oauth_initial_access_tokens_expires_at_idx").on(t.expiresAt)],
);

export const oauthRegistrationAccessTokens = sqliteTable(
  "oauth_registration_access_tokens",
  panvaModelCols,
  (t) => [index("oauth_registration_access_tokens_expires_at_idx").on(t.expiresAt)],
);

export const oauthInteractions = sqliteTable("oauth_interactions", panvaModelCols, (t) => [
  index("oauth_interactions_expires_at_idx").on(t.expiresAt),
]);

export const oauthReplayDetection = sqliteTable("oauth_replay_detection", panvaModelCols, (t) => [
  index("oauth_replay_detection_expires_at_idx").on(t.expiresAt),
]);

export const oauthPushedAuthorizationRequests = sqliteTable(
  "oauth_pushed_authorization_requests",
  panvaModelCols,
  (t) => [index("oauth_pushed_authorization_requests_expires_at_idx").on(t.expiresAt)],
);

export const oauthBackchannelAuthenticationRequests = sqliteTable(
  "oauth_backchannel_authentication_requests",
  panvaModelCols,
  (t) => [index("oauth_backchannel_authentication_requests_expires_at_idx").on(t.expiresAt)],
);

// Grants are persistent consent records — they never expire on their own,
// and `grant_id` is meaningless for the Grant model itself (the row *is*
// the grant). Both columns are populated as NULL here by the adapter; the
// uniform column shape is kept so a single adapter class handles every
// model type.
export const oauthGrants = sqliteTable("oauth_grants", panvaModelCols);

// ----- ShellWatch-owned table: JWKS signing key material -----

export const oauthSigningKeys = sqliteTable("oauth_signing_keys", {
  kid: text("kid").primaryKey(),
  alg: text("alg").notNull(),
  privateJwkCiphertext: text("private_jwk_ciphertext").notNull(),
  publicJwk: text("public_jwk", { mode: "json" }).notNull(),
  createdAt: text("created_at").notNull(),
  retiredAt: text("retired_at"),
});

// ----- Name → table lookup used by the adapter factory -----

export const panvaModelTables = {
  Session: oauthSessions,
  AccessToken: oauthAccessTokens,
  AuthorizationCode: oauthAuthorizationCodes,
  RefreshToken: oauthRefreshTokens,
  DeviceCode: oauthDeviceCodes,
  ClientCredentials: oauthClientCredentials,
  Client: oauthClients,
  InitialAccessToken: oauthInitialAccessTokens,
  RegistrationAccessToken: oauthRegistrationAccessTokens,
  Interaction: oauthInteractions,
  ReplayDetection: oauthReplayDetection,
  PushedAuthorizationRequest: oauthPushedAuthorizationRequests,
  BackchannelAuthenticationRequest: oauthBackchannelAuthenticationRequests,
  Grant: oauthGrants,
} as const;

export type PanvaModelName = keyof typeof panvaModelTables;
