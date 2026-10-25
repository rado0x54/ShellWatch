// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Control plane for the compose-managed targets (#244): exec into an sshd
 * container to install authorized_keys, read its VERBOSE auth log for a time
 * window, restart it. Thin wrappers over `docker compose`; the suite assumes
 * `pnpm e2e:up` (or the CI step) already brought the stack up.
 */
import { execFile, execFileSync, type ExecFileException } from "node:child_process";
import { createConnection } from "node:net";
import { COMPOSE_FILE, COMPOSE_PROJECT, SSHD, SSHD_USER, type SshdTarget } from "./env.js";
import { waitFor } from "./util.js";

const COMPOSE_BASE = ["compose", "-f", COMPOSE_FILE, "-p", COMPOSE_PROJECT];

export function compose(args: string[], input?: string): string {
  return execFileSync("docker", [...COMPOSE_BASE, ...args], {
    encoding: "utf8",
    input,
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 64 * 1024 * 1024,
  });
}

function composeAsync(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      "docker",
      [...COMPOSE_BASE, ...args],
      { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
      (err: ExecFileException | null, stdout: string, stderr: string) => {
        if (err)
          reject(new Error(`docker compose ${args.join(" ")} failed: ${stderr || err.message}`));
        else resolve(stdout);
      },
    );
  });
}

/** Run a shell command inside a service container (as root), optionally feeding stdin. */
export function exec(target: SshdTarget, script: string, stdin?: string): string {
  return compose(["exec", "-T", SSHD[target].service, "sh", "-c", script], stdin);
}

/** Replace a user's authorized_keys with the given lines. */
export function installAuthorizedKeys(target: SshdTarget, user: string, lines: string[]): void {
  const path = `/home/${user}/.ssh/authorized_keys`;
  exec(
    target,
    `cat > ${path} && chown ${user}:${user} ${path} && chmod 600 ${path}`,
    `${lines.join("\n")}\n`,
  );
}

/** Install the file key for `filekey` and the passkey for `passkey` on a target. */
export function installIdentities(
  target: SshdTarget,
  ids: { fileKeyLine?: string; passkeyLine?: string },
): void {
  if (ids.fileKeyLine) installAuthorizedKeys(target, SSHD_USER.fileKey, [ids.fileKeyLine]);
  if (ids.passkeyLine && SSHD[target].webauthnSk) {
    installAuthorizedKeys(target, SSHD_USER.passkey, [ids.passkeyLine]);
  }
}

/** sshd's log (stderr, `-e`) since an ISO timestamp — the per-test assertion window. */
export async function logsSince(target: SshdTarget, sinceIso: string): Promise<string> {
  return composeAsync([
    "logs",
    "--no-color",
    "--no-log-prefix",
    "--since",
    sinceIso,
    SSHD[target].service,
  ]);
}

/** Full logs for all services (dumped into e2e/out on failure). */
export async function allLogs(): Promise<string> {
  return composeAsync(["logs", "--no-color", "--timestamps"]);
}

export function waitForPort(host: string, port: number, timeoutMs = 30_000): Promise<true> {
  return waitFor(
    () =>
      new Promise<boolean>((resolve) => {
        const sock = createConnection({ host, port });
        sock.once("connect", () => {
          sock.destroy();
          resolve(true);
        });
        sock.once("error", () => resolve(false));
      }),
    { timeoutMs, intervalMs: 200, what: `${host}:${port} to accept connections` },
  );
}

/** Restart an sshd container (kills every live SSH connection) and wait until it listens again. */
export async function restart(target: SshdTarget): Promise<void> {
  await composeAsync(["restart", "-t", "1", SSHD[target].service]);
  await waitForPort(SSHD[target].host, SSHD[target].port);
}

/** OpenSSH version string of the server in a target container, e.g. "OpenSSH_10.6p1". */
export function sshdVersion(target: SshdTarget): string {
  const out = exec(target, "ssh -V 2>&1 || true");
  return out.trim().split(",")[0] ?? out.trim();
}

/**
 * Fail with a clear message if the compose stack isn't up. Tolerates a
 * container that is still re-running its healthcheck (e.g. right after the
 * restart scenario) by waiting up to 30 s for `healthy`.
 */
export async function assertStackUp(targets: SshdTarget[]): Promise<void> {
  const wanted = [...targets.map((t) => SSHD[t].service), "hydra"];
  let ps = "";
  try {
    await waitFor(
      () => {
        ps = compose(["ps", "--format", "{{.Service}} {{.Health}}"]);
        return wanted.every((svc) => new RegExp(`^${svc} healthy$`, "m").test(ps));
      },
      { timeoutMs: 30_000, intervalMs: 500, what: "e2e compose services to be healthy" },
    );
  } catch {
    const missing = wanted.filter((svc) => !new RegExp(`^${svc} healthy$`, "m").test(ps));
    throw new Error(
      `e2e stack not healthy (missing: ${missing.join(", ")}). Run \`pnpm e2e:up\` first.\n${ps}`,
    );
  }
}
