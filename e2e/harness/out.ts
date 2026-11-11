// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Observability hooks (#244): on any failure, dump the server's stdout/stderr,
 * `docker compose logs` for all services, and the per-test sshd log window into
 * e2e/out/<scenario>/ (git-ignored; uploaded as a CI artifact).
 */
import { appendFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, afterEach, onTestFailed } from "vitest";
import { outDirFor, type RunningServer } from "./server.js";
import { allLogs } from "./sshd.js";

export interface ScenarioRecorder {
  /** Mark the start of a test's sshd log window. */
  mark(): string;
  /** Append a free-form note to the scenario's notes.log (always written). */
  note(text: string): void;
}

/**
 * Wire vitest hooks so every failing test in the file produces a dump. Call at
 * the top of a `describe` that owns a server (pass a getter — the server starts
 * in beforeAll).
 */
export function recordScenario(
  scenario: string,
  server: () => RunningServer | undefined,
): ScenarioRecorder {
  const dir = outDirFor(scenario);
  const notes = join(dir, "notes.log");
  writeFileSync(notes, `# ${scenario} — ${new Date().toISOString()}\n`);
  let windowStart = new Date().toISOString();

  afterEach((ctx) => {
    onTestFailed(async () => {
      const name = ctx.task.name.replace(/[^a-z0-9]+/gi, "_").slice(0, 80);
      server()?.flushLog();
      try {
        writeFileSync(join(dir, `compose-${name}.log`), await allLogs());
      } catch (err) {
        appendFileSync(notes, `compose logs failed: ${(err as Error).message}\n`);
      }
      appendFileSync(notes, `FAILED ${ctx.task.name} (window from ${windowStart})\n`);
    });
  });

  afterAll(async () => {
    server()?.flushLog();
    try {
      writeFileSync(join(dir, "compose.log"), await allLogs());
    } catch {
      /* stack may already be down */
    }
  });

  return {
    mark() {
      windowStart = new Date().toISOString();
      return windowStart;
    },
    note(text) {
      appendFileSync(notes, `${new Date().toISOString()} ${text}\n`);
    },
  };
}
