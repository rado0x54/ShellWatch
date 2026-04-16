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
  type SigningKeyService,
  type ActiveSigningKey,
} from "./signing-keys.js";
