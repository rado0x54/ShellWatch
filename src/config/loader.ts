import { accessSync, constants, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { type Config, ConfigSchema } from "./schema.js";

export function loadConfig(configPath?: string): Config {
  const resolvedPath = resolve(configPath ?? process.env.SHELLWATCH_CONFIG ?? "config.yaml");

  let raw: string;
  try {
    raw = readFileSync(resolvedPath, "utf-8");
  } catch (err) {
    throw new Error(`Failed to read config file at ${resolvedPath}: ${(err as Error).message}`);
  }

  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    throw new Error(`Failed to parse YAML config at ${resolvedPath}: ${(err as Error).message}`);
  }

  const result = ConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`Invalid config at ${resolvedPath}:\n${issues}`);
  }

  const config = result.data;
  const configDir = dirname(resolvedPath);

  for (const server of config.servers) {
    const keyPath = resolve(configDir, server.privateKeyPath);
    try {
      accessSync(keyPath, constants.R_OK);
    } catch {
      throw new Error(`Private key for server "${server.id}" not readable at ${keyPath}`);
    }
    // Normalize to absolute path
    server.privateKeyPath = keyPath;
  }

  return config;
}
