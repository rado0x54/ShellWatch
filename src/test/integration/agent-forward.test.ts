import { createHash } from "node:crypto";
import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import ssh2 from "ssh2";

const { utils } = ssh2;

import { InMemoryEndpointRepository, InMemorySshKeyRepository } from "../../db/index.js";
import { TerminalManager } from "../../terminal/index.js";
import { ForwardingAgent } from "../../transport/forwarding-agent.js";
import { InMemoryKeyProvider } from "../../transport/key-directory-watcher.js";
import type { ScannedKey } from "../../transport/key-scanner.js";
import { SshTransportFactory } from "../../transport/ssh-transport-factory.js";
import { buildFileKeyEntry, CompositeSshAgent } from "../../webauthn/index.js";
import {
  createTestLog,
  startTestSshServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

describe("SSH Agent Forwarding", () => {
  let log: TestLog;
  let sshServer: TestSshServer;

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
  });

  afterAll(async () => {
    await sshServer?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  function buildTestInfra(agentForward: boolean) {
    const parsed = utils.parseKey(sshServer.clientPrivateKey);
    if (!parsed || parsed instanceof Error) throw new Error("Failed to parse test SSH key");
    const pubKeyBuf = parsed.getPublicSSH();
    const fingerprint = `SHA256:${createHash("sha256").update(pubKeyBuf).digest("base64url")}`;
    const publicKeyOpenSsh = `${parsed.type} ${pubKeyBuf.toString("base64")}`;

    const scannedKey: ScannedKey = {
      filename: "test-key.pem",
      path: "/tmp/test-key.pem",
      type: parsed.type,
      publicKeyOpenSsh,
      fingerprint,
      privateKeyContent: sshServer.clientPrivateKey,
    };

    const endpointRepo = new InMemoryEndpointRepository([
      {
        id: "test-server",
        label: "Test Server",
        host: sshServer.host,
        port: sshServer.port,
        username: "testuser",
      },
    ]);
    const keyRepo = new InMemorySshKeyRepository([
      { id: "test-key", label: "Test Key", type: "file", publicKey: publicKeyOpenSsh, fingerprint },
    ]);
    const keyProvider = new InMemoryKeyProvider([scannedKey]);

    const factory = new SshTransportFactory(endpointRepo, keyRepo, keyProvider, {
      rpId: "localhost",
      getAgentForward: async () => agentForward,
      isAdmin: () => true,
      createAgent: ({ fileKeys, agentForward: fwd }) => {
        const fileKeyEntries = fileKeys
          .map((fk) => buildFileKeyEntry(fk.privateKey))
          .filter((e) => e !== null);
        if (fileKeyEntries.length === 0) return null;
        const params = {
          passkeys: [],
          fileKeys: fileKeyEntries,
          rpId: "localhost",
          onSignRequest: () => {},
        };
        const agent = fwd ? new ForwardingAgent(params) : new CompositeSshAgent(params);
        return { agent, cleanup: () => agent.destroy() };
      },
    });

    const terminalManager = new TerminalManager(endpointRepo, (id) => factory.create(id), {
      idleTimeoutMs: 60_000,
      cleanupIntervalMs: 60_000,
    });

    return { terminalManager };
  }

  it("requests agent forwarding when enabled", async () => {
    const { terminalManager } = buildTestInfra(true);
    try {
      const session = await terminalManager.create("test-server", "ui");
      expect(session.status).toBe("open");

      // Give the SSH handshake a moment to complete the agent forward request
      await new Promise((r) => setTimeout(r, 100));

      expect(sshServer.agentForwardRequested).toBe(true);

      terminalManager.close(session.sessionId);
    } finally {
      terminalManager.destroy();
    }
  });

  it("does not request agent forwarding when disabled", async () => {
    // Close and restart the SSH server to reset state
    await sshServer.close();
    sshServer = await startTestSshServer(log);

    const { terminalManager } = buildTestInfra(false);
    try {
      const session = await terminalManager.create("test-server", "ui");
      expect(session.status).toBe("open");

      await new Promise((r) => setTimeout(r, 100));

      expect(sshServer.agentForwardRequested).toBe(false);

      terminalManager.close(session.sessionId);
    } finally {
      terminalManager.destroy();
    }
  });
});
