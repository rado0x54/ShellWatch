import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
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

const testCredential: WebAuthnCredentialInfo = {
  id: "cred-1",
  accountId: "account-1",
  credentialId: "base64url-credential-id",
  label: "YubiKey",
  publicKeyOpenSsh: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAA...",
  revoked: false,
};

const testScannedKey = {
  fingerprint: "SHA256:abc123",
  privateKeyContent: "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
};

const testRpId = "test.example.com";

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
        { rpId: testRpId },
      );

      await expect(factory.create("nonexistent")).rejects.toThrow("Unknown endpoint: nonexistent");
    });

    it("throws if key not found in repository", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([testEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        { rpId: testRpId },
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
        { rpId: testRpId },
      );

      const transport = await factory.create("ep-1");

      expect(transport).toBe(mockTransport);
      expect(mockConnectSsh).toHaveBeenCalledWith(
        expect.objectContaining({ host: "example.com", port: 22, username: "user" }),
        testScannedKey.privateKeyContent,
        {},
      );
    });

    it("throws if private key file not found in key store", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([testEndpoint]),
        new InMemorySshKeyRepository([testFileKey]),
        new InMemoryKeyProvider([]), // empty — no scanned keys
        { rpId: testRpId },
      );

      await expect(factory.create("ep-1")).rejects.toThrow("is unavailable");
    });
  });

  describe("webauthn key (via passkeyId)", () => {
    const passkeyEndpoint = { ...testEndpoint, keyId: undefined, passkeyId: "cred-1" };

    it("throws if no credential lookup provided", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([passkeyEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        { rpId: testRpId },
      );

      await expect(factory.create("ep-1")).rejects.toThrow(
        "WebAuthn key configured but no credential lookup provided",
      );
    });

    it("throws if no agent factory provided", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([passkeyEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        { rpId: testRpId, findCredential: () => testCredential },
      );

      await expect(factory.create("ep-1")).rejects.toThrow(
        "WebAuthn key configured but no agent factory provided",
      );
    });

    it("throws if credential is revoked", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([passkeyEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        {
          rpId: testRpId,
          findCredential: () => ({ ...testCredential, revoked: true }),
          createWebAuthnAgent: () => null,
        },
      );

      await expect(factory.create("ep-1")).rejects.toThrow("has been revoked");
    });

    it("throws if agent factory returns null (no browser)", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([passkeyEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        {
          rpId: testRpId,
          findCredential: () => testCredential,
          createWebAuthnAgent: () => null,
        },
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
        new InMemoryEndpointRepository([passkeyEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        { rpId: testRpId, findCredential: () => testCredential, createWebAuthnAgent },
      );

      const transport = await factory.create("ep-1");

      expect(transport).toBe(mockTransport);
      expect(createWebAuthnAgent).toHaveBeenCalledWith(testCredential, "test.example.com");
      expect(mockConnectSshWithAgent).toHaveBeenCalledWith(
        expect.objectContaining({ host: "example.com" }),
        mockAgent,
        { agentForward: false },
      );
    });

    it("calls cleanup when transport closes", async () => {
      const mockTransport = createMockTransport();
      const mockAgent = { sign: vi.fn() } as never;
      const cleanup = vi.fn();
      mockConnectSshWithAgent.mockResolvedValue(mockTransport);

      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([passkeyEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        {
          rpId: testRpId,
          findCredential: () => testCredential,
          createWebAuthnAgent: () => ({ agent: mockAgent, cleanup }),
        },
      );

      await factory.create("ep-1");

      expect(cleanup).not.toHaveBeenCalled();
      (mockTransport as unknown as EventEmitter).emit("close");
      expect(cleanup).toHaveBeenCalledOnce();
    });
  });

  describe("auto-negotiate (no key assigned)", () => {
    const autoEndpoint = {
      ...testEndpoint,
      keyId: undefined,
      accountId: "account-1",
    };

    it("throws if no composite agent factory provided", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([autoEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        { rpId: testRpId },
      );

      await expect(factory.create("ep-1")).rejects.toThrow(
        "No SSH key configured for endpoint and no auto-negotiate agent factory provided",
      );
    });

    it("throws if no keys available at all", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([autoEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        {
          rpId: testRpId,
          createAutoNegotiateAgent: () => null,
          findCredentialsForAccount: () => [],
          isAdmin: () => false,
        },
      );

      await expect(factory.create("ep-1")).rejects.toThrow("No SSH keys available");
    });

    it("gathers file keys for admin accounts", async () => {
      const mockTransport = createMockTransport();
      const mockAgent = { sign: vi.fn() } as never;
      const cleanup = vi.fn();
      mockConnectSshWithAgent.mockResolvedValue(mockTransport);

      const createAutoNegotiateAgent = vi.fn().mockReturnValue({ agent: mockAgent, cleanup });

      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([autoEndpoint]),
        new InMemorySshKeyRepository([testFileKey]),
        new InMemoryKeyProvider([testScannedKey]),
        {
          rpId: testRpId,
          createAutoNegotiateAgent,
          findCredentialsForAccount: () => [],
          isAdmin: () => true,
        },
      );

      await factory.create("ep-1");

      expect(createAutoNegotiateAgent).toHaveBeenCalledWith(
        expect.objectContaining({
          fileKeys: [
            { publicKey: testFileKey.publicKey, privateKey: testScannedKey.privateKeyContent },
          ],
          passkeys: [],
          isAdmin: true,
          rpId: testRpId,
        }),
      );
    });

    it("excludes file keys for non-admin accounts", async () => {
      const mockTransport = createMockTransport();
      const mockAgent = { sign: vi.fn() } as never;
      const cleanup = vi.fn();
      mockConnectSshWithAgent.mockResolvedValue(mockTransport);

      const createAutoNegotiateAgent = vi.fn().mockReturnValue({ agent: mockAgent, cleanup });

      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([autoEndpoint]),
        new InMemorySshKeyRepository([testFileKey]),
        new InMemoryKeyProvider([testScannedKey]),
        {
          rpId: testRpId,
          createAutoNegotiateAgent,
          findCredentialsForAccount: () => [testCredential],
          isAdmin: () => false,
        },
      );

      await factory.create("ep-1");

      expect(createAutoNegotiateAgent).toHaveBeenCalledWith(
        expect.objectContaining({
          fileKeys: [],
          passkeys: [testCredential],
        }),
      );
    });

    it("passes endpoint info to composite agent factory", async () => {
      const mockTransport = createMockTransport();
      const mockAgent = { sign: vi.fn() } as never;
      mockConnectSshWithAgent.mockResolvedValue(mockTransport);

      const createAutoNegotiateAgent = vi
        .fn()
        .mockReturnValue({ agent: mockAgent, cleanup: vi.fn() });

      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([autoEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        {
          rpId: testRpId,
          createAutoNegotiateAgent,
          findCredentialsForAccount: () => [testCredential],
          isAdmin: () => false,
        },
      );

      await factory.create("ep-1");

      expect(createAutoNegotiateAgent).toHaveBeenCalledWith(
        expect.objectContaining({
          endpoint: expect.objectContaining({
            id: "ep-1",
            host: "example.com",
            label: "Test Server",
          }),
        }),
      );
    });

    it("calls cleanup when transport closes", async () => {
      const mockTransport = createMockTransport();
      const mockAgent = { sign: vi.fn() } as never;
      const cleanup = vi.fn();
      mockConnectSshWithAgent.mockResolvedValue(mockTransport);

      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([autoEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        {
          rpId: testRpId,
          createAutoNegotiateAgent: () => ({ agent: mockAgent, cleanup }),
          findCredentialsForAccount: () => [testCredential],
          isAdmin: () => false,
        },
      );

      await factory.create("ep-1");

      expect(cleanup).not.toHaveBeenCalled();
      (mockTransport as unknown as EventEmitter).emit("close");
      expect(cleanup).toHaveBeenCalledOnce();
    });

    it("throws if composite factory returns null (no browser, no file keys)", async () => {
      const factory = new SshTransportFactory(
        new InMemoryEndpointRepository([autoEndpoint]),
        new InMemorySshKeyRepository([]),
        new InMemoryKeyProvider([]),
        {
          rpId: testRpId,
          createAutoNegotiateAgent: () => null,
          findCredentialsForAccount: () => [testCredential],
          isAdmin: () => false,
        },
      );

      await expect(factory.create("ep-1")).rejects.toThrow(
        "WebAuthn authentication requires a browser session",
      );
    });
  });
});
