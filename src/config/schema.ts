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
  sessionTtlSeconds: 86400,
  selfRegistrationEnabled: false,
  rateLimit: rateLimitDefaults,
};

export const SecuritySchema = z.object({
  rpId: z
    .string()
    .min(1, "security.rpId is required (e.g., 'localhost' or 'shellwatch.example.com')"),
  allowedNetworks: z.array(z.string()).default(securityFieldDefaults.allowedNetworks),
  sessionTtlSeconds: z.number().int().min(60).default(securityFieldDefaults.sessionTtlSeconds),
  cookieSecret: z.string().optional(),
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

// /demo/authorized-keys lookup endpoint. Pairs with shellwatch-demo-server's
// AuthorizedKeysCommand. Disabled by default; expose only on a network the
// demo container can reach — typically a Docker internal network. See #211.
export const demoAuthorizedKeysDefaults = {
  enabled: false,
  allowedNetworks: ["127.0.0.1/32", "::1/128"],
  cacheTtlSeconds: 30,
};

export const DemoAuthorizedKeysSchema = z.object({
  /** Master switch — registers the route only when true. */
  enabled: z.boolean().default(demoAuthorizedKeysDefaults.enabled),
  /**
   * Networks permitted to call /demo/authorized-keys. Should be only the
   * demo container's bridge subnet in production. Defaults to loopback for
   * local dev.
   */
  allowedNetworks: z.array(z.string()).default(demoAuthorizedKeysDefaults.allowedNetworks),
  /**
   * Optional shared-secret bearer the demo container must send in the
   * `Authorization: Bearer …` header. Defense-in-depth on top of the network
   * allowlist; omit to rely on the network control alone.
   */
  sharedSecret: z.string().min(16).optional(),
  /**
   * In-process cache TTL for the `(type, fingerprint) → credentials` index.
   * SSH pubkey auth invokes AuthorizedKeysCommand K+1 times per connect when
   * the client offers K keys; without caching that's K+1 DB scans.
   */
  cacheTtlSeconds: z
    .number()
    .int()
    .min(1)
    .max(3600)
    .default(demoAuthorizedKeysDefaults.cacheTtlSeconds),
});

export const ConfigSchema = z.object({
  keyDirectory: z.string().default("./keys"),
  seedAdminEndpoints: z.array(SeedEndpointSchema).default([]),
  seedAdminApiKey: z.string().optional(),
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
  demoAuthorizedKeys: DemoAuthorizedKeysSchema.default(demoAuthorizedKeysDefaults),
  vapid: VapidSchema.optional(),
});

export type SeedEndpoint = z.infer<typeof SeedEndpointSchema>;
export type DemoEndpoint = z.infer<typeof DemoEndpointSchema>;
export type Config = z.infer<typeof ConfigSchema>;
