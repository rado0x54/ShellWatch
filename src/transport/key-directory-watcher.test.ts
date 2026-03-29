import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { InMemorySshKeyRepository } from "../db/repositories/key-repo.js";
import { InMemoryKeyProvider, KeyDirectoryWatcher } from "./key-directory-watcher.js";

// A valid ed25519 private key for testing (generated, not used anywhere)
const TEST_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACADaynFqfxdSsyuyIhYTKERJHUViO3nJJXk1/oFicEg1gAAAJhRYPREUWD0
RAAAAAtzc2gtZWQyNTUxOQAAACADaynFqfxdSsyuyIhYTKERJHUViO3nJJXk1/oFicEg1g
AAAEBVEER3iHKQvZ8DtgCIIw3LNIB2FvKZ03MhtneVjjbDGgNrKcWp/F1KzK7IiFhMoREk
dRWI7eckleTX+gWJwSDWAAAAD3Rlc3RAc2hlbGx3YXRjaAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----`;

let tmpDir: string;
let keyRepo: InMemorySshKeyRepository;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "shellwatch-keywatcher-"));
  keyRepo = new InMemorySshKeyRepository([]);
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("KeyDirectoryWatcher", () => {
  it("discovers keys on initial scan", async () => {
    writeFileSync(join(tmpDir, "test.pem"), TEST_KEY, { mode: 0o600 });

    const watcher = new KeyDirectoryWatcher(tmpDir, keyRepo);
    const keys = await watcher.start();
    watcher.stop();

    expect(keys).toHaveLength(1);
    expect(keys[0].filename).toBe("test.pem");
    expect(keys[0].type).toBe("ssh-ed25519");
  });

  it("registers discovered keys in the repository", async () => {
    writeFileSync(join(tmpDir, "test.pem"), TEST_KEY, { mode: 0o600 });

    const watcher = new KeyDirectoryWatcher(tmpDir, keyRepo);
    await watcher.start();
    watcher.stop();

    const dbKeys = await keyRepo.findAll();
    expect(dbKeys).toHaveLength(1);
    expect(dbKeys[0].id).toBe("test");
    expect(dbKeys[0].type).toBe("file");
    expect(dbKeys[0].fingerprint).toMatch(/^SHA256:/);
  });

  it("does not duplicate keys on re-scan", async () => {
    writeFileSync(join(tmpDir, "test.pem"), TEST_KEY, { mode: 0o600 });

    const watcher1 = new KeyDirectoryWatcher(tmpDir, keyRepo);
    await watcher1.start();
    watcher1.stop();

    const watcher2 = new KeyDirectoryWatcher(tmpDir, keyRepo);
    await watcher2.start();
    watcher2.stop();

    const dbKeys = await keyRepo.findAll();
    expect(dbKeys).toHaveLength(1);
  });

  it("provides private key content by fingerprint", async () => {
    writeFileSync(join(tmpDir, "test.pem"), TEST_KEY, { mode: 0o600 });

    const watcher = new KeyDirectoryWatcher(tmpDir, keyRepo);
    const keys = await watcher.start();
    watcher.stop();

    const privateKey = watcher.getPrivateKey(keys[0].fingerprint);
    expect(privateKey).toBe(TEST_KEY);
  });

  it("returns undefined for unknown fingerprint", async () => {
    const watcher = new KeyDirectoryWatcher(tmpDir, keyRepo);
    await watcher.start();
    watcher.stop();

    expect(watcher.getPrivateKey("SHA256:nonexistent")).toBeUndefined();
  });

  it("ignores non-.pem files", async () => {
    writeFileSync(join(tmpDir, "readme.txt"), "not a key");
    writeFileSync(join(tmpDir, "key.pub"), "ssh-ed25519 AAAA...");

    const watcher = new KeyDirectoryWatcher(tmpDir, keyRepo);
    const keys = await watcher.start();
    watcher.stop();

    expect(keys).toHaveLength(0);
  });

  it("ignores invalid key files", async () => {
    writeFileSync(join(tmpDir, "bad.pem"), "this is not a valid key");

    const watcher = new KeyDirectoryWatcher(tmpDir, keyRepo);
    const keys = await watcher.start();
    watcher.stop();

    expect(keys).toHaveLength(0);
  });

  it("handles missing directory gracefully", async () => {
    const watcher = new KeyDirectoryWatcher("/tmp/nonexistent-dir-xyz", keyRepo);
    const keys = await watcher.start();
    watcher.stop();

    expect(keys).toHaveLength(0);
  });

  it("detects key added after start", async () => {
    const watcher = new KeyDirectoryWatcher(tmpDir, keyRepo);
    await watcher.start();

    expect(watcher.getAvailableKeys()).toHaveLength(0);

    // Add a key file
    writeFileSync(join(tmpDir, "new.pem"), TEST_KEY, { mode: 0o600 });

    // Wait for debounced watcher to pick it up
    await new Promise((resolve) => setTimeout(resolve, 1500));

    expect(watcher.getAvailableKeys()).toHaveLength(1);
    const dbKeys = await keyRepo.findAll();
    expect(dbKeys).toHaveLength(1);

    watcher.stop();
  });

  it("detects key removed after start", async () => {
    writeFileSync(join(tmpDir, "test.pem"), TEST_KEY, { mode: 0o600 });

    const watcher = new KeyDirectoryWatcher(tmpDir, keyRepo);
    const keys = await watcher.start();

    expect(watcher.isAvailable(keys[0].fingerprint)).toBe(true);

    // Remove the key file
    rmSync(join(tmpDir, "test.pem"));

    // Wait for debounced watcher to pick it up
    await new Promise((resolve) => setTimeout(resolve, 1500));

    expect(watcher.isAvailable(keys[0].fingerprint)).toBe(false);
    // Key stays in DB even though file is gone
    const dbKeys = await keyRepo.findAll();
    expect(dbKeys).toHaveLength(1);

    watcher.stop();
  });
});

describe("InMemoryKeyProvider", () => {
  it("returns private key by fingerprint", () => {
    const provider = new InMemoryKeyProvider([
      { fingerprint: "SHA256:abc", privateKeyContent: "key-content" },
    ]);

    expect(provider.getPrivateKey("SHA256:abc")).toBe("key-content");
  });

  it("returns undefined for unknown fingerprint", () => {
    const provider = new InMemoryKeyProvider([]);
    expect(provider.getPrivateKey("SHA256:unknown")).toBeUndefined();
  });
});
