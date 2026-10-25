// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Drives the Go agent-client (`shellwatch-agent`) and the host's `ssh` for the
 * agent-proxy scenarios (#244): the system-ssh path (#22/#36) in which `ssh`
 * talks to the agent's Unix socket, the agent relays SSH-agent frames to
 * /agent-proxy, and the human approves the signature in ShellWatch.
 */
import { type ChildProcess, execFile, execFileSync, spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { OUT_DIR, REPO_ROOT, SERVER_URL } from "./env.js";
import { sleep, waitFor } from "./util.js";

const AGENT_DIR = resolve(REPO_ROOT, "agent-client");

/**
 * Locate (or build) the agent binary: `E2E_AGENT_BIN`, then
 * agent-client/shellwatch-agent (what `make build` / the CI step produce),
 * else `go build` into e2e/out/bin.
 */
export function ensureAgentBinary(): string {
  if (process.env.E2E_AGENT_BIN) return process.env.E2E_AGENT_BIN;
  const prebuilt = join(AGENT_DIR, "shellwatch-agent");
  if (existsSync(prebuilt)) return prebuilt;
  const out = join(OUT_DIR, "bin", "shellwatch-agent");
  mkdirSync(join(OUT_DIR, "bin"), { recursive: true });
  if (!existsSync(out) || statSync(out).mtimeMs < newestMtime(join(AGENT_DIR, "internal"))) {
    execFileSync("go", ["build", "-o", out, "./cmd/shellwatch-agent"], {
      cwd: AGENT_DIR,
      stdio: "inherit",
    });
  }
  return out;
}

function newestMtime(dir: string): number {
  let newest = 0;
  const walk = (d: string) => {
    for (const entry of execFileSync("find", [d, "-type", "f", "-name", "*.go"], {
      encoding: "utf8",
    })
      .split("\n")
      .filter(Boolean)) {
      newest = Math.max(newest, statSync(entry).mtimeMs);
    }
  };
  walk(dir);
  return newest;
}

export interface AgentDaemon {
  socketPath: string;
  output(): string;
  stop(): Promise<void>;
}

/** Start `shellwatch-agent` in daemon mode and wait for its socket. */
export async function startAgentDaemon(opts: {
  /** Static bearer (`--token`). Omit to let the agent use its credential store. */
  token?: string;
  env?: Record<string, string>;
  socketPath?: string;
}): Promise<AgentDaemon> {
  const bin = ensureAgentBinary();
  // macOS caps sun_path at 104 bytes — keep the socket under a short temp dir.
  const socketPath = opts.socketPath ?? join(mkdtempSync(join(tmpdir(), "swe2e-")), "agent.sock");
  const args = ["--server", SERVER_URL, "--insecure", "--socket", socketPath];
  if (opts.token) args.push("--token", opts.token);
  const chunks: string[] = [];
  const child: ChildProcess = spawn(bin, args, {
    env: { ...process.env, ...opts.env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout!.on("data", (d: Buffer) => chunks.push(d.toString()));
  child.stderr!.on("data", (d: Buffer) => chunks.push(d.toString()));
  let exited = false;
  child.on("exit", () => (exited = true));
  await waitFor(
    () => {
      if (exited) throw new Error(`shellwatch-agent exited early:\n${chunks.join("")}`);
      return existsSync(socketPath);
    },
    { timeoutMs: 10_000, what: "agent socket" },
  );
  return {
    socketPath,
    output: () => chunks.join(""),
    async stop() {
      if (!exited) {
        child.kill("SIGTERM");
        const deadline = Date.now() + 5_000;
        while (!exited && Date.now() < deadline) await sleep(50);
        if (!exited) child.kill("SIGKILL");
      }
    },
  };
}

export interface CommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Run the host's `ssh` with the given agent socket; never prompts (BatchMode). */
export function runSsh(p: {
  socketPath: string;
  user: string;
  host: string;
  port: number;
  command: string;
  timeoutMs?: number;
  extraArgs?: string[];
}): Promise<CommandResult> {
  const args = [
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentitiesOnly=no",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=ERROR",
    "-o",
    "ConnectTimeout=10",
    "-o",
    `IdentityAgent=${p.socketPath}`,
    "-p",
    String(p.port),
    ...(p.extraArgs ?? []),
    `${p.user}@${p.host}`,
    p.command,
  ];
  return new Promise((resolveResult) => {
    execFile(
      "ssh",
      args,
      {
        env: { ...process.env, SSH_AUTH_SOCK: p.socketPath },
        timeout: p.timeoutMs ?? 90_000,
        encoding: "utf8",
      },
      (err, stdout, stderr) => {
        const code =
          err && typeof (err as { code?: unknown }).code === "number"
            ? (err as { code: number }).code
            : err
              ? null
              : 0;
        resolveResult({ code, stdout, stderr });
      },
    );
  });
}

/** `ssh-add -L` against the agent socket. */
export function sshAddList(socketPath: string): CommandResult {
  try {
    const stdout = execFileSync("ssh-add", ["-L"], {
      env: { ...process.env, SSH_AUTH_SOCK: socketPath },
      encoding: "utf8",
    });
    return { code: 0, stdout, stderr: "" };
  } catch (err) {
    const e = err as { status: number | null; stdout?: string; stderr?: string };
    return { code: e.status, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
}

/** Host OpenSSH client version, e.g. { major: 10, minor: 3 }. */
export function hostSshVersion(): { major: number; minor: number; raw: string } {
  // `ssh -V` prints to stderr.
  const probe = spawnSync("ssh", ["-V"], { encoding: "utf8" });
  const raw = `${probe.stderr ?? ""}${probe.stdout ?? ""}`;
  const m = /OpenSSH_(\d+)\.(\d+)/.exec(raw);
  return { major: m ? Number(m[1]) : 0, minor: m ? Number(m[2]) : 0, raw: raw.trim() };
}

/** Whether the host `ssh` can use webauthn-sk identities from an agent (OpenSSH >= 10.3). */
export function hostSshSupportsWebauthnSk(): boolean {
  const v = hostSshVersion();
  return v.major > 10 || (v.major === 10 && v.minor >= 3);
}

export interface AgentLoginRun {
  /** The authorize URL the agent tried to open in a browser. */
  authorizeUrl: string;
  /** Resolves with the process result once the loopback callback has been hit. */
  result: Promise<CommandResult>;
  env: Record<string, string>;
}

/**
 * Run `shellwatch-agent login` headlessly: a stub `xdg-open`/`open` on PATH
 * captures the authorize URL instead of launching a browser, the credential
 * store is redirected to a temp HOME/XDG dir, and the keyring is forced
 * unavailable so the 0600 file fallback is used (never the developer's real
 * keychain). The caller drives the captured URL through Hydra and finishes by
 * fetching the agent's loopback callback.
 */
export async function startAgentLogin(): Promise<AgentLoginRun> {
  const bin = ensureAgentBinary();
  const home = mkdtempSync(join(tmpdir(), "swe2e-home-"));
  const stubBin = join(home, "bin");
  mkdirSync(stubBin);
  const urlFile = join(home, "authorize-url.txt");
  for (const name of ["xdg-open", "open"]) {
    const path = join(stubBin, name);
    writeFileSync(path, `#!/bin/sh\nprintf '%s' "$1" > "${urlFile}"\n`);
    chmodSync(path, 0o755);
  }
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    PATH: `${stubBin}:${process.env.PATH ?? ""}`,
    HOME: home,
    XDG_CONFIG_HOME: join(home, ".config"),
    // Point the session bus somewhere dead so go-keyring reports "unavailable"
    // and the agent falls back to the file store under XDG_CONFIG_HOME.
    DBUS_SESSION_BUS_ADDRESS: "unix:path=/nonexistent/e2e-no-bus",
  };
  const chunks: string[] = [];
  const result = new Promise<CommandResult>((resolveResult) => {
    const child = spawn(bin, ["login", "--server", SERVER_URL, "--insecure"], {
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout!.on("data", (d: Buffer) => chunks.push(d.toString()));
    child.stderr!.on("data", (d: Buffer) => chunks.push(d.toString()));
    child.on("exit", (code) => resolveResult({ code, stdout: chunks.join(""), stderr: "" }));
  });
  const authorizeUrl = await waitFor(
    () => (existsSync(urlFile) ? readFileSync(urlFile, "utf8").trim() || null : null),
    { timeoutMs: 20_000, what: "agent login to open the authorize URL" },
  );
  return { authorizeUrl, result, env };
}
