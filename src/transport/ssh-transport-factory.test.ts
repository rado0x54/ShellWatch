// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import type { WebAuthnCredentialInfo } from "../db/repositories/credential-queries.js";
import type { EndpointInfo } from "../db/repositories/endpoint-repo.js";
import { InMemorySshKeyRepository } from "../db/repositories/key-repo.js";
import { InMemoryKeyProvider } from "./key-directory-watcher.js";
import { SshTransportFactory } from "./ssh-transport-factory.js";

// Mock the ssh connection function
vi.mock("./ssh-transport.js", () => ({
  connectSshWithAgent: vi.fn(),
}));

import { connectSshWithAgent } from "./ssh-transport.js";

const mockConnectSshWithAgent = vi.mocked(connectSshWithAgent);

const testEndpoint: EndpointInfo = {
  id: "ep-1",
  label: "Test Server",
  host: "example.com",
  port: 22,
  username: "user",
  accountId: "account-1",
  userVerification: "required",
  agentForward: false,
  description: null,
};

const testFileKey = {
  id: "key-1",
  label: "Test Key",
  type: "file",
  publicKeyOpenSsh: "ssh-ed25519 AAAA...",
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
  it("throws if no keys available", async () => {
    const factory = new SshTransportFactory(
      new InMemorySshKeyRepository([]),
      new InMemoryKeyProvider([]),
      {
        rpId: testRpId,
        createAgent: () => null,
        findCredentialsForAccount: () => [],
        isAdmin: () => false,
      },
    );

    await expect(
      factory.create({
        endpoint: testEndpoint,
        sessionId: "sess_test",
        trigger: { kind: "ui", sourceIp: "127.0.0.1" },
      }),
    ).rejects.toThrow("No SSH keys available");
  });

  it("throws if agent factory returns null (no keys)", async () => {
    const factory = new SshTransportFactory(
      new InMemorySshKeyRepository([]),
      new InMemoryKeyProvider([]),
      {
        rpId: testRpId,
        createAgent: () => null,
        findCredentialsForAccount: () => [testCredential],
        isAdmin: () => false,
      },
    );

    await expect(
      factory.create({
        endpoint: testEndpoint,
        sessionId: "sess_test",
        trigger: { kind: "ui", sourceIp: "127.0.0.1" },
      }),
    ).rejects.toThrow("No SSH keys available for this endpoint");
  });

  it("connects with agent and passes agentForward flag", async () => {
    const mockTransport = createMockTransport();
    const mockAgent = { sign: vi.fn() } as never;
    const cleanup = vi.fn();
    mockConnectSshWithAgent.mockResolvedValue(mockTransport);

    const createAgent = vi.fn().mockReturnValue({ agent: mockAgent, cleanup });

    const factory = new SshTransportFactory(
      new InMemorySshKeyRepository([testFileKey]),
      new InMemoryKeyProvider([testScannedKey]),
      {
        rpId: testRpId,
        createAgent,
        findCredentialsForAccount: () => [],
        isAdmin: () => true,
      },
    );

    const transport = await factory.create({
      endpoint: testEndpoint,
      sessionId: "sess_test",
      trigger: { kind: "ui", sourceIp: "127.0.0.1" },
    });

    expect(transport).toBe(mockTransport);
    expect(createAgent).toHaveBeenCalledWith(
      expect.objectContaining({
        fileKeys: [
          expect.objectContaining({
            publicKey: testFileKey.publicKeyOpenSsh,
            privateKey: testScannedKey.privateKeyContent,
            label: testFileKey.label,
            fingerprint: testFileKey.fingerprint,
          }),
        ],
        passkeys: [],
        isAdmin: true,
        rpId: testRpId,
        agentForward: false,
      }),
    );
    expect(mockConnectSshWithAgent).toHaveBeenCalledWith(
      expect.objectContaining({ host: "example.com" }),
      mockAgent,
      { agentForward: false },
    );
  });

  it("gathers file keys for admin, excludes for non-admin", async () => {
    const mockTransport = createMockTransport();
    const mockAgent = { sign: vi.fn() } as never;
    mockConnectSshWithAgent.mockResolvedValue(mockTransport);

    const createAgent = vi.fn().mockReturnValue({ agent: mockAgent, cleanup: vi.fn() });

    const factory = new SshTransportFactory(
      new InMemorySshKeyRepository([testFileKey]),
      new InMemoryKeyProvider([testScannedKey]),
      {
        rpId: testRpId,
        createAgent,
        findCredentialsForAccount: () => [testCredential],
        isAdmin: () => false,
      },
    );

    await factory.create({
      endpoint: testEndpoint,
      sessionId: "sess_test",
      trigger: { kind: "ui", sourceIp: "127.0.0.1" },
    });

    expect(createAgent).toHaveBeenCalledWith(
      expect.objectContaining({
        fileKeys: [],
        passkeys: [testCredential],
      }),
    );
  });

  it("calls cleanup when transport closes", async () => {
    const mockTransport = createMockTransport();
    const mockAgent = { sign: vi.fn() } as never;
    const cleanup = vi.fn();
    mockConnectSshWithAgent.mockResolvedValue(mockTransport);

    const factory = new SshTransportFactory(
      new InMemorySshKeyRepository([]),
      new InMemoryKeyProvider([]),
      {
        rpId: testRpId,
        createAgent: () => ({ agent: mockAgent, cleanup }),
        findCredentialsForAccount: () => [testCredential],
        isAdmin: () => false,
      },
    );

    await factory.create({
      endpoint: testEndpoint,
      sessionId: "sess_test",
      trigger: { kind: "ui", sourceIp: "127.0.0.1" },
    });

    expect(cleanup).not.toHaveBeenCalled();
    (mockTransport as unknown as EventEmitter).emit("close");
    expect(cleanup).toHaveBeenCalledOnce();
  });

  it("passes agentForward=true when the endpoint has it enabled", async () => {
    const mockTransport = createMockTransport();
    const mockAgent = { sign: vi.fn() } as never;
    mockConnectSshWithAgent.mockResolvedValue(mockTransport);

    const createAgent = vi.fn().mockReturnValue({ agent: mockAgent, cleanup: vi.fn() });

    const factory = new SshTransportFactory(
      new InMemorySshKeyRepository([]),
      new InMemoryKeyProvider([]),
      {
        rpId: testRpId,
        createAgent,
        findCredentialsForAccount: () => [testCredential],
        isAdmin: () => false,
      },
    );

    await factory.create({
      endpoint: { ...testEndpoint, agentForward: true },
      sessionId: "sess_test",
      trigger: { kind: "ui", sourceIp: "127.0.0.1" },
    });

    expect(createAgent).toHaveBeenCalledWith(expect.objectContaining({ agentForward: true }));
    expect(mockConnectSshWithAgent).toHaveBeenCalledWith(expect.anything(), mockAgent, {
      agentForward: true,
    });
  });
});
