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
    /** Master toggle. When false, the rest of this config is ignored and
     *  no routes are mounted. */
    enabled: z.boolean().default(false),

    /** Scopes advertised in metadata and accepted on /oidc/auth. */
    scopes: z.array(z.string().min(1)).default(["mcp", "agent"]),

    /**
     * DCR policy:
     *  - "open": anonymous POST to /oidc/reg. Best UX, matches MCP default.
     *  - "admin-only": requires a valid sw_session cookie on /oidc/reg.
     *  - "disabled": no DCR; clients must be pre-registered.
     */
    dynamicClientRegistration: z.enum(["open", "admin-only", "disabled"]).default("open"),

    /** Lifetimes in seconds. */
    accessTokenTtlSeconds: z.number().int().positive().default(3600),
    refreshTokenTtlSeconds: z
      .number()
      .int()
      .positive()
      .default(60 * 60 * 24 * 30),
    authorizationCodeTtlSeconds: z.number().int().positive().default(60),

    /**
     * Resource indicators bound into issued tokens (RFC 8707). Clients MUST
     * pass `resource=<one of these>` on /authorize.
     *
     * The literal token `${issuer}` is substituted with the runtime issuer
     * URL when the config is consumed by the Provider factory. Users who
     * override this list can either:
     *   - include `${issuer}` to get the same substitution, or
     *   - write a fully-qualified URL directly (e.g. "https://shellwatch.example/mcp").
     *
     * Written literally here because the issuer URL isn't known at config
     * load time — it's derived from the incoming request (reverse-proxy
     * aware) when the Provider is constructed.
     */
    resourceIndicators: z
      .array(z.string().min(1))
      .default(["${issuer}/mcp", "${issuer}/agent-proxy"]),

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
