import { z } from "zod";

export const SshKeySchema = z.object({
  id: z.string().min(1),
  label: z.string().min(1),
  privateKeyPath: z.string().min(1),
});

export const EndpointSchema = z.object({
  id: z.string().min(1),
  label: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).default(22),
  username: z.string().min(1),
  keyId: z.string().min(1),
});

export const SecuritySchema = z.object({
  allowedNetworks: z.array(z.string()).default(["127.0.0.1/32", "::1/128"]),
});

export const NotificationsSchema = z.object({
  mcp: z
    .object({
      debounceMs: z.number().int().min(10).max(5000).default(100),
    })
    .default({ debounceMs: 100 }),
});

export const ConfigSchema = z.object({
  keys: z.array(SshKeySchema).min(1, "At least one SSH key must be configured"),
  servers: z.array(EndpointSchema).min(1, "At least one server must be configured"),
  security: SecuritySchema.default({ allowedNetworks: ["127.0.0.1/32", "::1/128"] }),
  notifications: NotificationsSchema.default({ mcp: { debounceMs: 100 } }),
});

export type SshKey = z.infer<typeof SshKeySchema>;
export type Endpoint = z.infer<typeof EndpointSchema>;
export type Config = z.infer<typeof ConfigSchema>;
