import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { Client, type ClientChannel } from "ssh2";
import type { Config, Endpoint } from "../config/index.js";
import type { TerminalTransport, TransportFactory } from "../terminal/transport.js";

const CONNECTION_TIMEOUT = 10_000; // 10 seconds

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
    if (!this.stream) {
      throw new Error("SSH stream is not open");
    }
    this.stream.write(data);
  }

  resize(cols: number, rows: number): void {
    if (!this.stream) {
      throw new Error("SSH stream is not open");
    }
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

function connectSsh(endpoint: Endpoint): Promise<TerminalTransport> {
  return new Promise((resolve, reject) => {
    const client = new Client();
    const privateKey = readFileSync(endpoint.privateKeyPath, "utf-8");

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

    client.connect({
      host: endpoint.host,
      port: endpoint.port,
      username: endpoint.username,
      privateKey,
      readyTimeout: CONNECTION_TIMEOUT,
    });
  });
}

export function createSshTransportFactory(config: Config): TransportFactory {
  return async (endpointId: string) => {
    const endpoint = config.servers.find((s) => s.id === endpointId);
    if (!endpoint) {
      throw new Error(`Unknown endpoint: ${endpointId}`);
    }
    return connectSsh(endpoint);
  };
}
