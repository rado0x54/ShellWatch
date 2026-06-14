// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { z } from "zod";
import { parseEndpointAddress } from "../utils/endpoint-address.js";

export const SeedEndpointSchema = z.object({
  label: z.string().min(1),
  address: z
    .string()
    .min(1)
    .transform((addr) => parseEndpointAddress(addr)),
  /**
   * Whether to enable SSH agent forwarding on sessions to this endpoint.
   * Defaults to true — opt out per endpoint when the host disallows forwarding.
   */
  agentForward: z.boolean().default(true),
  /**
   * Optional free-form context. Surfaced to MCP agents via the
   * `shellwatch_manage_endpoints` list/read tool — the canonical place to
   * tell an agent what a given host is for. Bounded to the same 1000-char
   * cap the REST API enforces on user-created endpoints.
   */
  description: z.string().max(1000).optional(),
});

// demoEndpoints uses the same shape as seedAdminEndpoints — they're virtual,
// global endpoints merged into every account's endpoint list (toggle on the
// account row). See src/demo-endpoints/. Key delivery is a separate concern,
// not modeled per-endpoint.
export const DemoEndpointSchema = SeedEndpointSchema;

/** Field-level defaults for optional security settings (rpId and trustedWebauthnOrigins are required) */
export const rateLimitDefaults = {
  selfRegister: { max: 5, windowMinutes: 15 },
  passkeyRegister: { max: 10, windowMinutes: 15 },
  loginOptions: { max: 20, windowMinutes: 15 },
  loginVerify: { max: 10, windowMinutes: 15 },
};

export const securityFieldDefaults = {
  allowedNetworks: ["127.0.0.1/32", "::1/128"],
  selfRegistrationEnabled: false,
  rateLimit: rateLimitDefaults,
};

export const SecuritySchema = z.object({
  rpId: z
    .string()
    .min(1, "security.rpId is required (e.g., 'localhost' or 'shellwatch.example.com')"),
  allowedNetworks: z.array(z.string()).default(securityFieldDefaults.allowedNetworks),
  selfRegistrationEnabled: z.boolean().default(securityFieldDefaults.selfRegistrationEnabled),
  rateLimit: z
    .object({
      selfRegister: z
        .object({
          max: z.number().int().min(1).default(rateLimitDefaults.selfRegister.max),
          windowMinutes: z
            .number()
            .int()
            .min(1)
            .default(rateLimitDefaults.selfRegister.windowMinutes),
        })
        .default(rateLimitDefaults.selfRegister),
      passkeyRegister: z
        .object({
          max: z.number().int().min(1).default(rateLimitDefaults.passkeyRegister.max),
          windowMinutes: z
            .number()
            .int()
            .min(1)
            .default(rateLimitDefaults.passkeyRegister.windowMinutes),
        })
        .default(rateLimitDefaults.passkeyRegister),
      loginOptions: z
        .object({
          max: z.number().int().min(1).default(rateLimitDefaults.loginOptions.max),
          windowMinutes: z
            .number()
            .int()
            .min(1)
            .default(rateLimitDefaults.loginOptions.windowMinutes),
        })
        .default(rateLimitDefaults.loginOptions),
      loginVerify: z
        .object({
          max: z.number().int().min(1).default(rateLimitDefaults.loginVerify.max),
          windowMinutes: z
            .number()
            .int()
            .min(1)
            .default(rateLimitDefaults.loginVerify.windowMinutes),
        })
        .default(rateLimitDefaults.loginVerify),
    })
    .default(rateLimitDefaults),
  trustedWebauthnOrigins: z
    .array(
      z
        .string()
        .refine(
          (s) => s.startsWith("http://") || s.startsWith("https://"),
          "Each trustedWebauthnOrigins entry must start with http:// or https:// (e.g., 'https://shellwatch.example.com')",
        ),
    )
    .min(
      1,
      "security.trustedWebauthnOrigins requires at least one origin (e.g., 'https://shellwatch.example.com')",
    ),
});

const notificationDefaults = { mcp: { debounceMs: 100 } };

export const NotificationsSchema = z.object({
  mcp: z
    .object({
      debounceMs: z.number().int().min(10).max(5000).default(notificationDefaults.mcp.debounceMs),
    })
    .default(notificationDefaults.mcp),
});

export const serverDefaults = {
  port: 3000,
  trustProxy: false as boolean | number | string | string[],
};

export const ServerSchema = z.object({
  port: z.number().int().min(1).max(65535).default(serverDefaults.port),
  /** External URL for deep links (e.g., "https://shellwatch.example.com" or "http://localhost:3000"). */
  externalUrl: z
    .string()
    .url("server.externalUrl must be a valid URL (e.g., 'http://localhost:3000')"),
  /**
   * Trust X-Forwarded-* headers when ShellWatch sits behind a reverse proxy.
   * Passed straight to Fastify's `trustProxy` option.
   *  - `false` (default): ignore proxy headers; `request.ip` is the TCP peer.
   *  - `true`: trust all hops (only safe if the network path itself is trusted).
   *  - `number`: trust this many hops back from the connection.
   *  - CIDR string or array of CIDRs/IPs: trust hops from these proxies only.
   * For deployments behind a known proxy, prefer the CIDR form to avoid
   * client-side X-Forwarded-For spoofing.
   */
  trustProxy: z
    .union([z.boolean(), z.number().int().min(0), z.string().min(1), z.array(z.string().min(1))])
    .default(false),
});

export const SeedAdminPasskeySchema = z.object({
  credentialId: z.string().min(1),
  publicKeyHex: z.string().min(1), // COSE public key as hex
  counter: z.number().int().default(0),
  transports: z.array(z.string()).default([]),
  label: z.string().default("Admin Passkey"),
});

export const VapidSchema = z.object({
  subject: z.string().min(1, "vapid.subject is required (e.g., 'mailto:admin@example.com')"),
  publicKey: z.string().min(1, "vapid.publicKey is required (base64url-encoded VAPID public key)"),
  privateKey: z
    .string()
    .min(1, "vapid.privateKey is required (base64url-encoded VAPID private key)"),
});

export const AgentSocketSchema = z.object({
  /** Enable the WebSocket agent proxy endpoint (/agent-proxy) */
  proxyEnabled: z.boolean().default(false),
});

export const agentSocketDefaults = { proxyEnabled: false };

// --- Ory Hydra (issue #217) ---
// Hydra is the single OAuth2/OIDC authority for all delegated access. Every
// client — the web UI (a public PKCE SPA client), MCP clients, and the
// agent-client — uses the same DCR + authorization_code + PKCE flow with a
// passkey login + consent; the token's `sub` carries the account. ShellWatch is
// Hydra's login + consent provider. See docs/architecture.md.

/** The OAuth scope the web UI presents to call ShellWatch's own /api + /ws. */
export const UI_SCOPE = "ui";

export const hydraDcrDefaults = {
  // Scopes a mediated-DCR client may request. `mcp` for MCP clients, `agent`
  // for the agent-client (filtered out when the agent proxy is disabled).
  allowedScopes: ["mcp", "agent"],
  // Loopback only by default — the safe baseline for local MCP clients and the
  // loopback agent-client. Hosted clients (e.g. Claude.ai) must have their
  // callback added explicitly via config (see config.sample.yaml). RegExp
  // source strings, anchored at match time.
  redirectUriPatterns: [
    "^http://(127\\.0\\.0\\.1|localhost)(:\\d+)?(/.*)?$",
    "^http://\\[::1\\](:\\d+)?(/.*)?$",
  ],
};

export const HydraDcrSchema = z.object({
  /** Scopes a mediated-DCR client may request. Granted scope ⊆ this set. */
  allowedScopes: z.array(z.string().min(1)).default(hydraDcrDefaults.allowedScopes),
  /** RegExp source strings; a client's redirect_uri must match at least one. */
  redirectUriPatterns: z.array(z.string().min(1)).default(hydraDcrDefaults.redirectUriPatterns),
});

export const hydraDefaults = {
  // 60s — at self-hosted scale the introspection load is trivial, so the cache
  // mostly amortizes bursts. The trade is revocation latency: a revoked /
  // logged-out token keeps working for up to this long. Lower it for tighter
  // revocation; 0 disables the cache (introspect every request).
  introspectionCacheTtlMs: 60_000,
};

export const HydraSchema = z.object({
  /**
   * Hydra PUBLIC issuer URL (e.g. "http://localhost:4444"). Advertised in
   * discovery, embedded in tokens, and used by the browser SPA + agent-client
   * for the authorization-code/refresh exchange. Must match Hydra's configured
   * `urls.self.issuer`.
   */
  publicUrl: z.string().url("hydra.publicUrl must be a valid URL (e.g. 'http://localhost:4444')"),
  /**
   * Hydra ADMIN API URL (e.g. "http://localhost:4445"). Used for login/consent
   * acceptance, client CRUD, and token introspection. MUST be reachable only
   * over a trusted network — never internet-exposed.
   */
  adminUrl: z.string().url("hydra.adminUrl must be a valid URL (e.g. 'http://localhost:4445')"),
  /** The first-party PUBLIC client the web UI (SPA) uses for its PKCE flow. No secret. */
  spa: z
    .object({
      clientId: z.string().min(1).default("shellwatch-web"),
      /**
       * Redirect URI registered for the SPA's authorization-code flow. Defaults
       * to `${server.externalUrl}/auth/callback` (filled in by the loader).
       */
      redirectUri: z.string().url().optional(),
    })
    .default({ clientId: "shellwatch-web" }),
  /** Bearer-introspection result cache TTL (ms). Caps revocation latency; default 60s. */
  introspectionCacheTtlMs: z
    .number()
    .int()
    .min(0)
    .max(300_000)
    .default(hydraDefaults.introspectionCacheTtlMs),
  dcr: HydraDcrSchema.default(hydraDcrDefaults),
});

export const ConfigSchema = z.object({
  keyDirectory: z.string().default("./keys"),
  seedAdminEndpoints: z.array(SeedEndpointSchema).default([]),
  seedAdminPasskeys: z.array(SeedAdminPasskeySchema).default([]),
  /**
   * Virtual demo endpoints merged into every account's endpoint list when the
   * account's showDemoEndpoints toggle is on. Same shape as seedAdminEndpoints
   * but never copied into the endpoints table — config is the source of truth.
   */
  demoEndpoints: z.array(DemoEndpointSchema).default([]),
  server: ServerSchema,
  security: SecuritySchema,
  notifications: NotificationsSchema.default(notificationDefaults),
  agentSocket: AgentSocketSchema.default(agentSocketDefaults),
  /**
   * Ory Hydra is a hard runtime dependency (#217) — the OAuth2/OIDC authority
   * for the web UI, MCP clients, and the agent-client, all via mediated DCR +
   * authorization_code + PKCE with a passkey login. There is no fallback shim.
   */
  hydra: HydraSchema,
  vapid: VapidSchema.optional(),
});

export type SeedEndpoint = z.infer<typeof SeedEndpointSchema>;
export type DemoEndpoint = z.infer<typeof DemoEndpointSchema>;
export type HydraConfig = z.infer<typeof HydraSchema>;
export type Config = z.infer<typeof ConfigSchema>;
