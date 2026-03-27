import { z } from "zod";

export const EndpointSchema = z.object({
  id: z.string().min(1),
  label: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).default(22),
  username: z.string().min(1),
  privateKeyPath: z.string().min(1),
});

export const ConfigSchema = z.object({
  servers: z.array(EndpointSchema).min(1, "At least one server must be configured"),
});

export type Endpoint = z.infer<typeof EndpointSchema>;
export type Config = z.infer<typeof ConfigSchema>;
