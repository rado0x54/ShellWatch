import { z } from "zod";

export const SeedEndpointSchema = z.object({
  label: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).default(22),
  username: z.string().min(1),
  passkeyCredentialRef: z.string().optional(), // references a passkey by its credentialId
});

export const securityDefaults = {
  allowedNetworks: ["127.0.0.1/32", "::1/128"],
  sessionTtlSeconds: 86400,
  trustedWebauthnOrigins: [] as string[],
};

export const SecuritySchema = z.object({
  allowedNetworks: z.array(z.string()).default(securityDefaults.allowedNetworks),
  sessionTtlSeconds: z.number().int().min(60).default(securityDefaults.sessionTtlSeconds),
  cookieSecret: z.string().optional(),
  trustedWebauthnOrigins: z.array(z.string()).default([]),
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
  trustedForwardedHostHeader: z.string().optional(),
  trustedForwardedProtoHeader: z.string().optional(),
});

export const SeedAdminPasskeySchema = z.object({
  credentialId: z.string().min(1),
  publicKeyHex: z.string().min(1), // COSE public key as hex
  counter: z.number().int().default(0),
  transports: z.array(z.string()).default([]),
  label: z.string().default("Admin Passkey"),
});

export const ConfigSchema = z.object({
  keyDirectory: z.string().default("./keys"),
  seedAdminEndpoints: z.array(SeedEndpointSchema).default([]),
  seedAdminApiKey: z.string().optional(),
  seedAdminPasskey: SeedAdminPasskeySchema.optional(),
  server: ServerSchema.default(serverDefaults),
  security: SecuritySchema.default(securityDefaults),
  notifications: NotificationsSchema.default(notificationDefaults),
});

export type SeedEndpoint = z.infer<typeof SeedEndpointSchema>;
export type Config = z.infer<typeof ConfigSchema>;
