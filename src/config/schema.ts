import { z } from "zod";

export const EndpointSchema = z.object({
  id: z.string().min(1),
  label: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).default(22),
  username: z.string().min(1),
});

export const securityDefaults = {
  allowedNetworks: ["127.0.0.1/32", "::1/128"],
  sessionTtlSeconds: 86400,
};

export const SecuritySchema = z.object({
  allowedNetworks: z.array(z.string()).default(securityDefaults.allowedNetworks),
  sessionTtlSeconds: z.number().int().min(60).default(securityDefaults.sessionTtlSeconds),
  cookieSecret: z.string().optional(),
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

export const ConfigSchema = z.object({
  keyDirectory: z.string().default("./keys"),
  seedServers: z.array(EndpointSchema).default([]),
  server: ServerSchema.default(serverDefaults),
  security: SecuritySchema.default(securityDefaults),
  notifications: NotificationsSchema.default(notificationDefaults),
});

export type Endpoint = z.infer<typeof EndpointSchema>;
export type Config = z.infer<typeof ConfigSchema>;
