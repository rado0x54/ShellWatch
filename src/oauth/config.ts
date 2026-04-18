import { z } from "zod";

/**
 * Zod schema for the `oauth` section of config.yaml. All fields have
 * sensible defaults — an empty `oauth: {}` block produces a spec-conformant,
 * secure configuration.
 *
 * The schema itself is just shape + validation. Wiring it into the main
 * config loader happens in a later PR so the scaffold PR stays self-contained.
 */
export const OAuthConfigSchema = z
  .object({
    /**
     * Scopes advertised in metadata and accepted on /oidc/auth.
     *
     * OAuth is always mounted when the server has a database — it
     * underpins the Web UI session cookie, `/mcp` auth, and the
     * third-party DCR flow. There is deliberately no `enabled` flag:
     * the only way to run ShellWatch without OAuth is to run it
     * without a database, which means no UI and no persisted state
     * (test / headless-MCP harnesses only).
     */
    scopes: z.array(z.string().min(1)).default(["mcp", "agent"]),

    /**
     * DCR policy:
     *  - "open": anonymous POST to /oidc/reg. Best UX, matches MCP default.
     *  - "disabled": no DCR; clients must be pre-registered.
     *
     * An `"admin-only"` mode that gates /oidc/reg on a valid `sw_session`
     * cookie is planned but not yet implemented — it requires the
     * cookie-session verifier landed by a later PR. The enum is
     * deliberately narrow here so an operator setting `admin-only` gets a
     * parse error instead of silent `open` behaviour.
     */
    dynamicClientRegistration: z.enum(["open", "disabled"]).default("open"),

    /** Lifetimes in seconds. */
    accessTokenTtlSeconds: z.number().int().positive().default(3600),
    refreshTokenTtlSeconds: z
      .number()
      .int()
      .positive()
      .default(60 * 60 * 24 * 30),
    authorizationCodeTtlSeconds: z.number().int().positive().default(60),

    /**
     * Resource indicators bound into issued tokens (RFC 8707). Clients
     * pass `resource=<one of these>` on /authorize; if they omit the
     * parameter the first entry is used as the default.
     *
     * The literal token `${baseUrl}` is substituted at runtime with the
     * server's external URL (e.g. `http://localhost:3000`). Users who
     * override this list can either:
     *   - include `${baseUrl}` to get the same substitution, or
     *   - write a fully-qualified URL directly (e.g. "https://shellwatch.example/mcp").
     */
    resourceIndicators: z
      .array(z.string().min(1))
      .default(["${baseUrl}/mcp", "${baseUrl}/agent-proxy"]),

    /**
     * JWKS rotation cadence. New key becomes active every
     * `signingKeyRotationDays`; old key stays valid for
     * `signingKeyOverlapDays` after rotation so in-flight tokens still
     * verify. Overlap MUST be strictly less than rotation (enforced below).
     */
    signingKeyRotationDays: z.number().int().positive().default(90),
    signingKeyOverlapDays: z.number().int().positive().default(30),

    /** Per-IP rate limit on /oidc/reg (anonymous DCR). */
    registrationRateLimitPerMinute: z.number().int().positive().default(10),
  })
  .strict()
  .refine((cfg) => cfg.signingKeyOverlapDays < cfg.signingKeyRotationDays, {
    message: "signingKeyOverlapDays must be less than signingKeyRotationDays",
    path: ["signingKeyOverlapDays"],
  });

export type OAuthConfig = z.infer<typeof OAuthConfigSchema>;

/** Default config as would apply when the `oauth` block is absent. */
export const defaultOAuthConfig: OAuthConfig = OAuthConfigSchema.parse({});
