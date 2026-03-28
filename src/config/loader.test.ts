import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "./loader.js";

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "shellwatch-test-"));
}

function writeConfig(dir: string, yaml: string): string {
  const configPath = join(dir, "config.yaml");
  writeFileSync(configPath, yaml);
  return configPath;
}

describe("loadConfig", () => {
  it("loads a valid config", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
keyDirectory: ./keys
servers:
  - id: test
    label: Test
    host: localhost
    port: 22
    username: user
    keyId: test-key
`,
    );

    const config = loadConfig(configPath);
    expect(config.servers).toHaveLength(1);
    expect(config.servers[0].id).toBe("test");
    expect(config.servers[0].keyId).toBe("test-key");
    expect(config.keyDirectory).toBe(join(dir, "keys"));
  });

  it("defaults port to 22", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
servers:
  - id: test
    label: Test
    host: localhost
    username: user
    keyId: k1
`,
    );

    const config = loadConfig(configPath);
    expect(config.servers[0].port).toBe(22);
  });

  it("defaults keyDirectory to ./keys", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
servers:
  - id: test
    label: Test
    host: localhost
    username: user
    keyId: k1
`,
    );

    const config = loadConfig(configPath);
    expect(config.keyDirectory).toBe(join(dir, "keys"));
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

  it("throws on missing required fields", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
servers:
  - id: test
`,
    );
    expect(() => loadConfig(configPath)).toThrow("Invalid config");
  });

  it("throws on empty servers list", () => {
    const dir = createTempDir();
    const configPath = writeConfig(dir, "servers: []");
    expect(() => loadConfig(configPath)).toThrow("Invalid config");
  });

  it("loads multiple servers", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
servers:
  - id: server1
    label: Server 1
    host: host1.example.com
    port: 22
    username: user1
    keyId: shared-key
  - id: server2
    label: Server 2
    host: host2.example.com
    port: 2222
    username: user2
    keyId: shared-key
`,
    );

    const config = loadConfig(configPath);
    expect(config.servers).toHaveLength(2);
    expect(config.servers[0].keyId).toBe("shared-key");
    expect(config.servers[1].port).toBe(2222);
  });
});
