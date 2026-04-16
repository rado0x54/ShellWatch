/**
 * OAuth module — single entry point.
 *
 * See docs/oauth-mcp.md for the full design. The module is built up across
 * multiple PRs on feature/oauth; nothing here is wired into the running
 * application yet. Each public export is consumed later by `registerOAuth`
 * in a subsequent PR.
 */
export { OAuthConfigSchema, defaultOAuthConfig, type OAuthConfig } from "./config.js";
export { panvaModelTables, type PanvaModelName } from "./adapter/schema.js";
export { DrizzleOidcAdapter, createDrizzleAdapterFactory } from "./adapter/drizzle-adapter.js";
export {
  createSigningKeyService,
  deriveEncryptionKey,
  type SigningKeyService,
  type ActiveSigningKey,
} from "./signing-keys.js";
export { createOAuthProvider, FIRST_PARTY_CLIENT_ID } from "./provider.js";
export { mountOAuthProvider } from "./mount.js";
export { registerOAuth, type RegisterOAuthParams, type RegisterOAuthResult } from "./register.js";
export {
  createFirstPartyTokenMinter,
  FIRST_PARTY_GRANT_TYPE,
  type FirstPartyTokenMinter,
  type FirstPartyTokenMinterOptions,
  type MintFirstPartyTokenInput,
  type MintedFirstPartyTokens,
} from "./first-party.js";
export {
  ACCESS_COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  clearFirstPartyCookies,
  setFirstPartyCookies,
} from "./cookie.js";
export {
  createUiSessionService,
  type UiSessionService,
  type UiSessionServiceDeps,
} from "./ui-session.js";
