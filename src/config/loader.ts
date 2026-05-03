// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { type Config, ConfigSchema } from "./schema.js";

export function loadConfig(configPath?: string): Config {
  const resolvedPath = resolve(configPath ?? process.env.SHELLWATCH_CONFIG ?? "config.yaml");

  let raw: string;
  try {
    raw = readFileSync(resolvedPath, "utf-8");
  } catch (err) {
    throw new Error(`Failed to read config file at ${resolvedPath}: ${(err as Error).message}`, {
      cause: err,
    });
  }

  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    throw new Error(`Failed to parse YAML config at ${resolvedPath}: ${(err as Error).message}`, {
      cause: err,
    });
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

  // Normalize keyDirectory to absolute path
  config.keyDirectory = resolve(configDir, config.keyDirectory);

  return config;
}
