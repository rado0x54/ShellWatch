import { execSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Connection, Server, type ServerChannel } from "ssh2";
import type { TestLog } from "./test-log.js";

export interface TestSshServer {
  port: number;
  host: string;
  hostKey: string;
  clientPublicKey: string;
  clientPrivateKey: string;
  /** Push data from the server side to all active shell streams */
  pushOutput(data: string): void;
  /** Simulate server disconnect — forcefully close all client connections */
  disconnectAll(): void;
  close(): Promise<void>;
}

function generateSshKeypair(): { privateKey: string; publicKey: string } {
  const dir = mkdtempSync(join(tmpdir(), "shellwatch-keygen-"));
  const keyPath = join(dir, "key");
  execSync(`ssh-keygen -t ed25519 -f ${keyPath} -N "" -q`);
  return {
    privateKey: readFileSync(keyPath, "utf-8"),
    publicKey: readFileSync(`${keyPath}.pub`, "utf-8"),
  };
}

/**
 * Simple shell command processor for the test SSH server.
 * Handles semicolon-separated commands, echo, and basic variable expansion.
 */
function processLine(stream: ServerChannel, line: string, log: TestLog): void {
  log.add("ssh-server", "executing line", line);
  let lastExitCode = 0;

  // Split on semicolons for chained commands
  const commands = line.split(";").map((c) => c.trim());

  for (const cmd of commands) {
    if (!cmd) continue;

    // Handle echo with variable substitution
    if (cmd.startsWith("echo ")) {
      let arg = cmd.slice(5).trim();
      // Remove surrounding quotes
      if (
        (arg.startsWith('"') && arg.endsWith('"')) ||
        (arg.startsWith("'") && arg.endsWith("'"))
      ) {
        arg = arg.slice(1, -1);
      }
      // Replace $? with last exit code
      arg = arg.replace(/\$\?/g, String(lastExitCode));
      stream.write(`${arg}\n`);
    } else if (cmd.startsWith("echo")) {
      stream.write("\n");
    } else {
      // Unknown command — write error and set exit code
      stream.write(`-bash: ${cmd.split(" ")[0]}: command not found\n`);
      lastExitCode = 127;
    }
  }
}

export async function startTestSshServer(log: TestLog): Promise<TestSshServer> {
  const hostKeyPair = generateSshKeypair();
  const clientKeyPair = generateSshKeypair();

  const activeStreams = new Set<ServerChannel>();
  const activeConnections = new Set<Connection>();

  const server = new Server({ hostKeys: [hostKeyPair.privateKey] }, (client) => {
    log.add("ssh-server", "client connected");
    activeConnections.add(client);

    client.on("authentication", (ctx) => {
      if (ctx.method === "publickey") {
        log.add("ssh-server", `auth: publickey for ${ctx.username}`);
        ctx.accept();
      } else {
        log.add("ssh-server", `auth: rejected method ${ctx.method}`);
        ctx.reject(["publickey"]);
      }
    });

    client.on("ready", () => {
      log.add("ssh-server", "client ready");

      client.on("session", (accept) => {
        const session = accept();

        session.on("pty", (accept) => {
          log.add("ssh-server", "pty requested");
          accept();
        });

        session.on("shell", (accept) => {
          log.add("ssh-server", "shell opened");
          const stream = accept();
          activeStreams.add(stream);

          // Simple shell: accumulate a line buffer and execute on newline
          let lineBuffer = "";

          stream.on("data", (data: Buffer) => {
            const text = data.toString();
            log.add("ssh-server", "received input", text);

            // Echo raw input back (terminal echo)
            stream.write(data);

            for (const char of text) {
              if (char === "\r" || char === "\n") {
                if (lineBuffer.length > 0) {
                  processLine(stream, lineBuffer.trim(), log);
                  lineBuffer = "";
                }
              } else {
                lineBuffer += char;
              }
            }
          });

          stream.on("close", () => {
            log.add("ssh-server", "shell stream closed");
            activeStreams.delete(stream);
          });
        });

        session.on("window-change", (accept, _reject, info) => {
          log.add("ssh-server", "window-change", info);
          accept();
        });
      });
    });

    client.on("close", () => {
      log.add("ssh-server", "client disconnected");
      activeConnections.delete(client);
    });

    client.on("error", (err) => {
      log.add("ssh-server", "client error", err.message);
    });
  });

  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("Failed to get server address"));
        return;
      }
      log.add("ssh-server", `listening on port ${addr.port}`);

      resolve({
        port: addr.port,
        host: "127.0.0.1",
        hostKey: hostKeyPair.privateKey,
        clientPublicKey: clientKeyPair.publicKey,
        clientPrivateKey: clientKeyPair.privateKey,
        pushOutput(data: string) {
          log.add("ssh-server", "pushing output", data);
          for (const stream of activeStreams) {
            stream.write(data);
          }
        },
        disconnectAll() {
          log.add("ssh-server", "disconnecting all clients");
          for (const conn of activeConnections) {
            conn.end();
          }
        },
        async close() {
          for (const stream of activeStreams) {
            stream.close();
          }
          activeStreams.clear();
          return new Promise<void>((res) => server.close(() => res()));
        },
      });
    });
  });
}
