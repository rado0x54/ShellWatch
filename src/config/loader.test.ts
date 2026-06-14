// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "./loader.js";

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "shellwatch-test-"));
}

// Hydra is a required config section (#217). Append a minimal block to every
// fixture that doesn't already set one, so these tests stay focused on the
// fields they actually exercise.
const HYDRA_YAML = `
hydra:
  publicUrl: http://localhost:4444
  adminUrl: http://localhost:4445
  spa:
    clientId: shellwatch-web
`;

function writeConfig(dir: string, yaml: string): string {
  const configPath = join(dir, "config.yaml");
  writeFileSync(configPath, yaml.includes("\nhydra:") ? yaml : yaml + HYDRA_YAML);
  return configPath;
}

describe("loadConfig", () => {
  it("loads a valid config with address format", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
keyDirectory: ./keys
server:
  externalUrl: http://localhost:3000
security:
  rpId: localhost
  trustedWebauthnOrigins:
    - http://localhost
seedAdminEndpoints:
  - label: Test
    address: user@localhost:22
`,
    );

    const config = loadConfig(configPath);
    expect(config.seedAdminEndpoints).toHaveLength(1);
    expect(config.seedAdminEndpoints[0].label).toBe("Test");
    expect(config.seedAdminEndpoints[0].address).toEqual({
      username: "user",
      host: "localhost",
      port: 22,
    });
    expect(config.keyDirectory).toBe(join(dir, "keys"));
  });

  it("defaults port to 22 and username to shellwatch", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
server:
  externalUrl: http://localhost:3000
security:
  rpId: localhost
  trustedWebauthnOrigins:
    - http://localhost
seedAdminEndpoints:
  - label: Test
    address: example.com
`,
    );

    const config = loadConfig(configPath);
    expect(config.seedAdminEndpoints[0].address.port).toBe(22);
    expect(config.seedAdminEndpoints[0].address.username).toBe("shellwatch");
  });

  it("defaults keyDirectory to ./keys", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
server:
  externalUrl: http://localhost:3000
security:
  rpId: localhost
  trustedWebauthnOrigins:
    - http://localhost
seedAdminEndpoints:
  - label: Test
    address: localhost
`,
    );

    const config = loadConfig(configPath);
    expect(config.keyDirectory).toBe(join(dir, "keys"));
  });

  it("defaults seedAdminEndpoints to empty array", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      "keyDirectory: ./keys\nserver:\n  externalUrl: http://localhost:3000\nsecurity:\n  rpId: localhost\n  trustedWebauthnOrigins:\n    - http://localhost\n",
    );

    const config = loadConfig(configPath);
    expect(config.seedAdminEndpoints).toEqual([]);
  });

  it("throws on missing config file", () => {
    expect(() => loadConfig("/nonexistent/config.yaml")).toThrow("Failed to read config");
  });

  it("throws on invalid YAML", () => {
    const dir = createTempDir();
    const configPath = join(dir, "config.yaml");
    writeFileSync(configPath, ": : : invalid yaml [[[");
    expect(() => loadConfig(configPath)).toThrow("Failed to parse YAML");
  });

  it("throws on missing required fields in seedAdminEndpoints entries", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
server:
  externalUrl: http://localhost:3000
security:
  rpId: localhost
  trustedWebauthnOrigins:
    - http://localhost
seedAdminEndpoints:
  - label: test
`,
    );
    expect(() => loadConfig(configPath)).toThrow("Invalid config");
  });

  it("defaults agentForward to true on seed endpoints", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
server:
  externalUrl: http://localhost:3000
security:
  rpId: localhost
  trustedWebauthnOrigins:
    - http://localhost
seedAdminEndpoints:
  - label: Default
    address: host.example.com
  - label: NoForward
    address: locked.example.com
    agentForward: false
`,
    );

    const config = loadConfig(configPath);
    expect(config.seedAdminEndpoints[0].agentForward).toBe(true);
    expect(config.seedAdminEndpoints[1].agentForward).toBe(false);
  });

  it("loads multiple endpoints with different address formats", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
server:
  externalUrl: http://localhost:3000
security:
  rpId: localhost
  trustedWebauthnOrigins:
    - http://localhost
seedAdminEndpoints:
  - label: Server 1
    address: host1.example.com
  - label: Server 2
    address: deploy@host2.example.com:2222
`,
    );

    const config = loadConfig(configPath);
    expect(config.seedAdminEndpoints).toHaveLength(2);
    expect(config.seedAdminEndpoints[1].address).toEqual({
      username: "deploy",
      host: "host2.example.com",
      port: 2222,
    });
  });
});
