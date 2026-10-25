// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Launches the server under test as a child process from the built binary
 * (`shellwatch`, see e2e/scripts/ensure-build.mjs) with a generated config and
 * a fresh SQLite file, waits for `/health`, and collects stdout/stderr (#244).
 * Nothing here imports the server's code — the launch command is the only
 * implementation-specific knob.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { writeServerConfig, type ServerConfigOptions } from "./config.js";
import { OUT_DIR, REPO_ROOT, SERVER_PORT, SERVER_URL } from "./env.js";
import { generateFileKey, type FileKeyIdentity } from "./identity.js";
import { sleep, waitFor } from "./util.js";

export interface StartServerOptions extends Omit<ServerConfigOptions, "keyDirectory"> {
  /** Scenario name — names the log file under e2e/out/<scenario>/. */
  scenario: string;
  /** Generate an ed25519 file key into the key directory before boot. Default true. */
  withFileKey?: boolean;
}

export interface RunningServer {
  url: string;
  dataDir: string;
  keyDirectory: string;
  configPath: string;
  fileKey: FileKeyIdentity | null;
  /** Everything the process wrote so far (slog lines + stderr). */
  output(): string;
  /** Persist the captured output to e2e/out/<scenario>/server.log. */
  flushLog(): string;
  stop(): Promise<void>;
}

/**
 * The server binary: `E2E_SERVER_BIN`, else what ensure-build.mjs produces
 * (`e2e/out/bin/shellwatch`), else a root `shellwatch` from `pnpm build`.
 */
export function serverBinary(): string {
  if (process.env.E2E_SERVER_BIN) return resolve(REPO_ROOT, process.env.E2E_SERVER_BIN);
  const built = resolve(OUT_DIR, "bin", "shellwatch");
  if (existsSync(built)) return built;
  return resolve(REPO_ROOT, "shellwatch");
}

export function outDirFor(scenario: string): string {
  const dir = resolve(OUT_DIR, scenario);
  mkdirSync(dir, { recursive: true });
  return dir;
}

export async function startServer(opts: StartServerOptions): Promise<RunningServer> {
  const bin = serverBinary();
  if (!existsSync(bin)) {
    throw new Error(`server binary missing — run \`pnpm build\` first (${bin})`);
  }

  const dataDir = mkdtempSync(join(tmpdir(), `shellwatch-e2e-${opts.scenario}-`));
  const keyDirectory = join(dataDir, "keys");
  mkdirSync(keyDirectory, { mode: 0o700 });
  const fileKey = (opts.withFileKey ?? true) ? generateFileKey(keyDirectory) : null;
  const configPath = writeServerConfig(dataDir, { ...opts, keyDirectory });

  const chunks: string[] = [];
  const child: ChildProcess = spawn(bin, ["-config", configPath], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      SHELLWATCH_DB: `sqlite:${join(dataDir, "shellwatch.db")}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout!.on("data", (d: Buffer) => chunks.push(d.toString()));
  child.stderr!.on("data", (d: Buffer) => chunks.push(d.toString()));
  let exited: { code: number | null; signal: NodeJS.Signals | null } | null = null;
  child.on("exit", (code, signal) => (exited = { code, signal }));

  const output = () => chunks.join("");
  const flushLog = () => {
    const file = join(outDirFor(opts.scenario), "server.log");
    writeFileSync(file, output());
    return file;
  };

  try {
    await waitFor(
      async () => {
        if (exited) {
          throw new Error(`server exited early (code ${exited.code}, signal ${exited.signal})`);
        }
        const res = await fetch(`${SERVER_URL}/health`).catch(() => null);
        return res?.ok ?? false;
      },
      { timeoutMs: 30_000, intervalMs: 200, what: `${SERVER_URL}/health` },
    );
  } catch (err) {
    flushLog();
    child.kill("SIGKILL");
    throw new Error(`${(err as Error).message}\n--- server output ---\n${output()}`, {
      cause: err,
    });
  }

  return {
    url: SERVER_URL,
    dataDir,
    keyDirectory,
    configPath,
    fileKey,
    output,
    flushLog,
    async stop() {
      if (!exited) {
        child.kill("SIGTERM");
        const deadline = Date.now() + 10_000;
        while (!exited && Date.now() < deadline) await sleep(50);
        if (!exited) child.kill("SIGKILL");
      }
      flushLog();
      // Make sure the port is really free before the next scenario boots.
      await waitFor(
        async () => {
          const res = await fetch(`${SERVER_URL}/health`).catch(() => null);
          return res === null;
        },
        { timeoutMs: 10_000, intervalMs: 100, what: `port ${SERVER_PORT} to be released` },
      );
    },
  };
}
