/**
 * OAuth module — single entry point.
 *
 * See docs/oauth-mcp.md for the full design. This PR lands the dependency,
 * schema, and config skeleton only. Subsequent PRs wire in panva's Provider,
 * the Drizzle adapter, the verifier chain, interaction routes, and the
 * first-party token minter, all behind `oauth.enabled`.
 */
export { OAuthConfigSchema, defaultOAuthConfig, type OAuthConfig } from "./config.js";
export { panvaModelTables, type PanvaModelName } from "./adapter/schema.js";
