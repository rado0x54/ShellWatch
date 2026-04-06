import { z } from "zod";
import { parseEndpointAddress } from "../utils/endpoint-address.js";

export const SeedEndpointSchema = z.object({
  label: z.string().min(1),
  address: z
    .string()
    .min(1)
    .transform((addr) => parseEndpointAddress(addr)),
  passkeyCredentialRef: z.string().optional(), // references a passkey by its credentialId
});

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
  basePath: "",
};

export const ServerSchema = z.object({
  port: z.number().int().min(1).max(65535).default(serverDefaults.port),
  basePath: z
    .string()
    .default(serverDefaults.basePath)
    .transform((v) => v.replace(/\/+$/, "")),
});

export const SeedAdminPasskeySchema = z.object({
  credentialId: z.string().min(1),
  publicKeyHex: z.string().min(1), // COSE public key as hex
  counter: z.number().int().default(0),
  transports: z.array(z.string()).default([]),
  label: z.string().default("Admin Passkey"),
});

export const AgentSocketSchema = z.object({
  /** Enable the WebSocket agent proxy endpoint (/agent-proxy) */
  proxyEnabled: z.boolean().default(false),
});

export const agentSocketDefaults = { proxyEnabled: false };

export const ConfigSchema = z.object({
  keyDirectory: z.string().default("./keys"),
  seedAdminEndpoints: z.array(SeedEndpointSchema).default([]),
  seedAdminApiKey: z.string().optional(),
  seedAdminPasskey: SeedAdminPasskeySchema.optional(),
  server: ServerSchema.default(serverDefaults),
  security: SecuritySchema,
  notifications: NotificationsSchema.default(notificationDefaults),
  agentSocket: AgentSocketSchema.default(agentSocketDefaults),
});

export type SeedEndpoint = z.infer<typeof SeedEndpointSchema>;
export type Config = z.infer<typeof ConfigSchema>;
