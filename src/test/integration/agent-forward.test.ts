import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import ssh2 from "ssh2";

const { utils } = ssh2;

import { InMemoryEndpointRepository, InMemorySshKeyRepository } from "../../db/index.js";
import { TerminalManager } from "../../terminal/index.js";
import { ForwardingAgent } from "../../transport/forwarding-agent.js";
import { InMemoryKeyProvider } from "../../transport/key-directory-watcher.js";
import type { ScannedKey } from "../../transport/key-scanner.js";
import { SshTransportFactory } from "../../transport/ssh-transport-factory.js";
import { sha256Fingerprint } from "../../webauthn/fingerprint.js";
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

  async function buildTestInfra(agentForward: boolean) {
    const parsed = utils.parseKey(sshServer.clientPrivateKey);
    if (!parsed || parsed instanceof Error) throw new Error("Failed to parse test SSH key");
    const pubKeyBuf = parsed.getPublicSSH();
    const fingerprint = sha256Fingerprint(pubKeyBuf);
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

    const factory = new SshTransportFactory(keyRepo, keyProvider, {
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
        const agent = fwd
          ? new ForwardingAgent({
              ...params,
              forwardingOnSignRequest: () => {},
              forwardingOnFileKeySignRequest: () => {},
            })
          : new CompositeSshAgent(params);
        return { agent, cleanup: () => agent.destroy() };
      },
    });

    const terminalManager = new TerminalManager((p) => factory.create(p), {
      idleTimeoutMs: 60_000,
      cleanupIntervalMs: 60_000,
    });

    const testEndpoint = (await endpointRepo.findById("test-server"))!;
    return { terminalManager, testEndpoint };
  }

  /** Poll until condition is true or timeout (avoids flaky setTimeout in CI) */
  async function waitFor(fn: () => boolean, timeoutMs = 2000, intervalMs = 10): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!fn()) {
      if (Date.now() > deadline) throw new Error("waitFor timed out");
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }

  it("requests agent forwarding when enabled", async () => {
    sshServer.resetAgentForwardRequested();
    const { terminalManager, testEndpoint } = await buildTestInfra(true);
    try {
      const session = await terminalManager.create(testEndpoint, {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      expect(session.status).toBe("open");

      await waitFor(() => sshServer.agentForwardRequested);
      expect(sshServer.agentForwardRequested).toBe(true);

      terminalManager.close(session.sessionId);
    } finally {
      terminalManager.destroy();
    }
  });

  it("does not request agent forwarding when disabled", async () => {
    sshServer.resetAgentForwardRequested();
    const { terminalManager, testEndpoint } = await buildTestInfra(false);
    try {
      const session = await terminalManager.create(testEndpoint, {
        kind: "ui",
        sourceIp: "127.0.0.1",
      });
      expect(session.status).toBe("open");

      // Give enough time for the handshake to complete — if forwarding were
      // requested it would happen within the first few ms after shell open
      await new Promise((r) => setTimeout(r, 100));

      expect(sshServer.agentForwardRequested).toBe(false);

      terminalManager.close(session.sessionId);
    } finally {
      terminalManager.destroy();
    }
  });
});
