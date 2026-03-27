import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "./loader.js";

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), "shellwatch-test-"));
}

function writeConfig(dir: string, yaml: string, keyFiles: string[] = []): string {
  const configPath = join(dir, "config.yaml");
  writeFileSync(configPath, yaml);
  const keysDir = join(dir, "keys");
  mkdirSync(keysDir, { recursive: true });
  for (const keyFile of keyFiles) {
    writeFileSync(join(keysDir, keyFile), "fake-key-content");
  }
  return configPath;
}

describe("loadConfig", () => {
  const dirs: string[] = [];

  afterEach(() => {
    // Cleanup is handled by OS temp dir
  });

  it("loads a valid config", () => {
    const dir = createTempDir();
    dirs.push(dir);
    const configPath = writeConfig(
      dir,
      `
servers:
  - id: test
    label: Test
    host: localhost
    port: 22
    username: user
    privateKeyPath: ./keys/test.pem
`,
      ["test.pem"],
    );

    const config = loadConfig(configPath);
    expect(config.servers).toHaveLength(1);
    expect(config.servers[0].id).toBe("test");
    expect(config.servers[0].host).toBe("localhost");
    expect(config.servers[0].privateKeyPath).toBe(join(dir, "keys", "test.pem"));
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
    privateKeyPath: ./keys/test.pem
`,
      ["test.pem"],
    );

    const config = loadConfig(configPath);
    expect(config.servers[0].port).toBe(22);
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

  it("throws on missing private key file", () => {
    const dir = createTempDir();
    const configPath = writeConfig(
      dir,
      `
servers:
  - id: test
    label: Test
    host: localhost
    port: 22
    username: user
    privateKeyPath: ./keys/nonexistent.pem
`,
    );
    expect(() => loadConfig(configPath)).toThrow("not readable");
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
    privateKeyPath: ./keys/key1.pem
  - id: server2
    label: Server 2
    host: host2.example.com
    port: 2222
    username: user2
    privateKeyPath: ./keys/key2.pem
`,
      ["key1.pem", "key2.pem"],
    );

    const config = loadConfig(configPath);
    expect(config.servers).toHaveLength(2);
    expect(config.servers[0].id).toBe("server1");
    expect(config.servers[1].port).toBe(2222);
  });
});
