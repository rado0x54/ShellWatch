import { EventEmitter } from "node:events";
import ssh2 from "ssh2";

type Client = ssh2.Client;
type ClientChannel = ssh2.ClientChannel;
const { Client } = ssh2;

import type { EndpointInfo, EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { SshKeyRepository } from "../db/repositories/key-repo.js";
import type { TerminalTransport, TransportFactory } from "../terminal/transport.js";
import type { WebAuthnSshAgent } from "../webauthn/ssh-agent.js";
import type { ForwardingAgent } from "./forwarding-agent.js";
import type { KeyStore } from "./key-scanner.js";

const CONNECTION_TIMEOUT = 10_000;

const DEFAULT_PTY = {
  term: "xterm-256color",
  cols: 80,
  rows: 24,
};

class SshTransport extends EventEmitter implements TerminalTransport {
  private client: Client;
  private stream: ClientChannel | null = null;

  constructor(client: Client, stream: ClientChannel) {
    super();
    this.client = client;
    this.stream = stream;

    stream.on("data", (data: Buffer) => {
      this.emit("data", data.toString("utf-8"));
    });

    stream.stderr.on("data", (data: Buffer) => {
      this.emit("data", data.toString("utf-8"));
    });

    stream.on("close", () => {
      this.stream = null;
      this.client.end();
      this.emit("close");
    });

    client.on("error", (err: Error) => {
      this.emit("error", err);
    });

    client.on("close", () => {
      if (this.stream) {
        this.stream = null;
        this.emit("close");
      }
    });
  }

  write(data: string): void {
    if (!this.stream) throw new Error("SSH stream is not open");
    this.stream.write(data);
  }

  resize(cols: number, rows: number): void {
    if (!this.stream) throw new Error("SSH stream is not open");
    this.stream.setWindow(rows, cols, rows * 16, cols * 8);
  }

  close(): void {
    if (this.stream) {
      this.stream.close();
      this.stream = null;
    }
    this.client.end();
  }
}

export interface AgentForwardOptions {
  /** Enable SSH agent forwarding (ssh -A) */
  agentForward?: boolean;
  /** Agent to forward to the remote host — must implement getStream() for forwarding */
  forwardingAgent?: ForwardingAgent;
}

export function connectSsh(
  endpoint: EndpointInfo,
  privateKey: string,
  options?: AgentForwardOptions,
): Promise<TerminalTransport> {
  return new Promise((resolve, reject) => {
    const client = new Client();

    const timeout = setTimeout(() => {
      client.end();
      reject(new Error(`Connection to ${endpoint.host}:${endpoint.port} timed out`));
    }, CONNECTION_TIMEOUT);

    client.on("ready", () => {
      clearTimeout(timeout);

      client.shell(
        {
          term: DEFAULT_PTY.term,
          cols: DEFAULT_PTY.cols,
          rows: DEFAULT_PTY.rows,
        },
        (err, stream) => {
          if (err) {
            client.end();
            reject(new Error(`Failed to open shell on ${endpoint.host}: ${err.message}`));
            return;
          }
          resolve(new SshTransport(client, stream));
        },
      );
    });

    client.on("error", (err) => {
      clearTimeout(timeout);
      reject(
        new Error(`SSH connection to ${endpoint.host}:${endpoint.port} failed: ${err.message}`),
      );
    });

    const connectOpts: Record<string, unknown> = {
      host: endpoint.host,
      port: endpoint.port,
      username: endpoint.username,
      privateKey,
      readyTimeout: CONNECTION_TIMEOUT,
    };

    if (options?.agentForward && options.forwardingAgent) {
      connectOpts.agent = options.forwardingAgent;
      connectOpts.agentForward = true;
    }

    client.connect(connectOpts as Parameters<typeof client.connect>[0]);
  });
}

const WEBAUTHN_CONNECTION_TIMEOUT = 90_000; // 90s — allows time for user to touch the key

export interface AgentConnectOptions {
  agentForward?: boolean;
  /** When agentForward is true, wrap the auth agent in a ForwardingAgent for getStream() support */
  forwardingAgent?: ForwardingAgent;
}

export function connectSshWithAgent(
  endpoint: EndpointInfo,
  agent: WebAuthnSshAgent,
  options?: AgentConnectOptions,
): Promise<TerminalTransport> {
  return new Promise((resolve, reject) => {
    const client = new Client();

    const timeout = setTimeout(() => {
      client.end();
      reject(
        new Error(
          `Connection to ${endpoint.host}:${endpoint.port} timed out (waiting for WebAuthn)`,
        ),
      );
    }, WEBAUTHN_CONNECTION_TIMEOUT);

    client.on("ready", () => {
      clearTimeout(timeout);

      client.shell(
        { term: DEFAULT_PTY.term, cols: DEFAULT_PTY.cols, rows: DEFAULT_PTY.rows },
        (err, stream) => {
          if (err) {
            client.end();
            reject(new Error(`Failed to open shell on ${endpoint.host}: ${err.message}`));
            return;
          }
          resolve(new SshTransport(client, stream));
        },
      );
    });

    client.on("error", (err) => {
      clearTimeout(timeout);
      reject(
        new Error(`SSH connection to ${endpoint.host}:${endpoint.port} failed: ${err.message}`),
      );
    });

    // When agent forwarding is enabled and a ForwardingAgent is provided,
    // use it as the agent — it delegates auth to the underlying agent and
    // provides getStream() for ssh2's auth-agent channel handler.
    const effectiveAgent =
      options?.agentForward && options.forwardingAgent ? options.forwardingAgent : agent;

    client.connect({
      host: endpoint.host,
      port: endpoint.port,
      username: endpoint.username,
      agent: effectiveAgent as unknown as string, // BaseAgent/ForwardingAgent — ssh2's isAgent() accepts this
      agentForward: options?.agentForward ?? false,
      readyTimeout: WEBAUTHN_CONNECTION_TIMEOUT,
    });
  });
}

export interface TransportFactoryOptions {
  /** Called to create a WebAuthn agent for a given key — returns null if no browser is available */
  createWebAuthnAgent?: (
    keys: import("../db/repositories/key-repo.js").SshKeyInfo[],
    rpId: string,
  ) => WebAuthnSshAgent | null;
}

export function createSshTransportFactory(
  endpointRepo: EndpointRepository,
  keyRepo: SshKeyRepository,
  keyStore: KeyStore,
  options: TransportFactoryOptions = {},
): TransportFactory {
  return async (endpointId: string) => {
    const endpoint = await endpointRepo.findById(endpointId);
    if (!endpoint) {
      throw new Error(`Unknown endpoint: ${endpointId}`);
    }
    if (!endpoint.keyId) {
      throw new Error(`No SSH key configured for endpoint ${endpointId}`);
    }

    const keyInfo = await keyRepo.findById(endpoint.keyId);
    if (!keyInfo) {
      throw new Error(`SSH key "${endpoint.keyId}" not found`);
    }

    // WebAuthn key — use browser-based signing
    if (keyInfo.type === "webauthn") {
      if (!options.createWebAuthnAgent) {
        throw new Error("WebAuthn key configured but no agent factory provided");
      }
      const agent = options.createWebAuthnAgent([keyInfo], "localhost");
      if (!agent) {
        throw new Error(
          "WebAuthn authentication requires a browser session. Open ShellWatch in a browser.",
        );
      }
      return connectSshWithAgent(endpoint, agent);
    }

    // File-based key — use private key from key directory
    const scannedKey = keyStore.findByFingerprint(keyInfo.fingerprint);
    if (!scannedKey) {
      throw new Error(
        `No private key file found for key "${endpoint.keyId}" (fingerprint: ${keyInfo.fingerprint}). ` +
          "Ensure the corresponding .pem file is in the key directory.",
      );
    }

    return connectSsh(endpoint, scannedKey.privateKeyContent);
  };
}
