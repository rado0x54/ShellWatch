import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { InMemoryEndpointRepository } from "../db/repositories/endpoint-repo.js";
import { InMemorySshKeyRepository } from "../db/repositories/key-repo.js";
import { InMemoryKeyProvider } from "./key-directory-watcher.js";
import { SshTransportFactory } from "./ssh-transport-factory.js";

// Mock the ssh connection functions — we don't want real SSH connections in unit tests
vi.mock("./ssh-transport.js", () => ({
  connectSsh: vi.fn(),
  connectSshWithAgent: vi.fn(),
}));

import { connectSsh, connectSshWithAgent } from "./ssh-transport.js";

const mockConnectSsh = vi.mocked(connectSsh);
const mockConnectSshWithAgent = vi.mocked(connectSshWithAgent);

const testEndpoint = {
  id: "ep-1",
  label: "Test Server",
  host: "example.com",
  port: 22,
  username: "user",
  keyId: "key-1",
};

const testFileKey = {
  id: "key-1",
  label: "Test Key",
  type: "file",
  publicKey: "ssh-ed25519 AAAA...",
  fingerprint: "SHA256:abc123",
};

const testWebAuthnKey = {
  id: "key-2",
  label: "YubiKey",
  type: "webauthn",
  publicKey: "webauthn-sk-ecdsa...",
  fingerprint: "SHA256:xyz789",
};

const testScannedKey = {
  fingerprint: "SHA256:abc123",
  privateKeyContent: "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
};

function createMockTransport() {
  return Object.assign(new EventEmitter(), {
    write: vi.fn(),
    resize: vi.fn(),
    close: vi.fn(),
  }) as never;
}

describe("SshTransportFactory", () => {
  describe("create()", () => {
    it("throws for unknown endpoint", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
      );

      await expect(factory.create("nonexistent")).rejects.toThrow("Unknown endpoint: nonexistent");
    });

    it("throws if endpoint has no keyId", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([{ ...testEndpoint, keyId: undefined }]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
      );

      await expect(factory.create("ep-1")).rejects.toThrow("No SSH key configured for endpoint");
    });

    it("throws if key not found in repository", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([testEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
      );

      await expect(factory.create("ep-1")).rejects.toThrow('SSH key "key-1" not found');
    });
  });

  describe("file-based key", () => {
    it("connects with private key from key store", async () => {
      const mockTransport = createMockTransport();
      mockConnectSsh.mockResolvedValue(mockTransport);

      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([testEndpoint]),
        new InMemorySshKeyRepository([testFileKey]),
        new InMemoryKeyProvider([testScannedKey]),
      );

      const transport = await factory.create("ep-1");

      expect(transport).toBe(mockTransport);
      expect(mockConnectSsh).toHaveBeenCalledWith(
        expect.objectContaining({ host: "example.com", port: 22, username: "user" }),
        testScannedKey.privateKeyContent,
      );
    });

    it("throws if private key file not found in key store", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([testEndpoint]),
        new InMemorySshKeyRepository([testFileKey]),
        new InMemoryKeyProvider([]), // empty — no scanned keys
      );

      await expect(factory.create("ep-1")).rejects.toThrow("is unavailable");
    });
  });

  describe("webauthn key", () => {
    it("throws if no agent factory provided", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([{ ...testEndpoint, keyId: "key-2" }]),
        new InMemorySshKeyRepository([testWebAuthnKey]),
        new InMemoryKeyProvider([]),
      );

      await expect(factory.create("ep-1")).rejects.toThrow(
        "WebAuthn key configured but no agent factory provided",
      );
    });

    it("throws if agent factory returns null (no browser)", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([{ ...testEndpoint, keyId: "key-2" }]),
        new InMemorySshKeyRepository([testWebAuthnKey]),
        new InMemoryKeyProvider([]),
        { createWebAuthnAgent: () => null },
      );

      await expect(factory.create("ep-1")).rejects.toThrow(
        "WebAuthn authentication requires a browser session",
      );
    });

    it("connects with agent when factory returns one", async () => {
      const mockTransport = createMockTransport();
      const mockAgent = { sign: vi.fn() } as never;
      const cleanup = vi.fn();
      mockConnectSshWithAgent.mockResolvedValue(mockTransport);

      const createWebAuthnAgent = vi.fn().mockReturnValue({ agent: mockAgent, cleanup });

      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([{ ...testEndpoint, keyId: "key-2" }]),
        new InMemorySshKeyRepository([testWebAuthnKey]),
        new InMemoryKeyProvider([]),
        { createWebAuthnAgent },
      );

      const transport = await factory.create("ep-1");

      expect(transport).toBe(mockTransport);
      expect(createWebAuthnAgent).toHaveBeenCalledWith([testWebAuthnKey], "localhost");
      expect(mockConnectSshWithAgent).toHaveBeenCalledWith(
        expect.objectContaining({ host: "example.com" }),
        mockAgent,
      );
    });

    it("calls cleanup when transport closes", async () => {
      const mockTransport = createMockTransport();
      const mockAgent = { sign: vi.fn() } as never;
      const cleanup = vi.fn();
      mockConnectSshWithAgent.mockResolvedValue(mockTransport);

      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([{ ...testEndpoint, keyId: "key-2" }]),
        new InMemorySshKeyRepository([testWebAuthnKey]),
        new InMemoryKeyProvider([]),
        { createWebAuthnAgent: () => ({ agent: mockAgent, cleanup }) },
      );

      await factory.create("ep-1");

      expect(cleanup).not.toHaveBeenCalled();
      (mockTransport as unknown as EventEmitter).emit("close");
      expect(cleanup).toHaveBeenCalledOnce();
    });
  });
});
