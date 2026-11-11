// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Collects log entries during a test and dumps them on failure.
 * Usage:
 *   const log = createTestLog();
 *   log.add("ssh", "client connected");
 *   // In afterEach or onTestFailed:
 *   log.dumpIfFailed(testContext);
 */
export interface TestLog {
  add(source: string, message: string, data?: unknown): void;
  dump(): void;
  clear(): void;
}

interface LogEntry {
  time: number;
  source: string;
  message: string;
  data?: unknown;
}

export function createTestLog(): TestLog {
  const entries: LogEntry[] = [];

  return {
    add(source: string, message: string, data?: unknown) {
      entries.push({ time: Date.now(), source, message, data });
    },
    dump() {
      if (entries.length === 0) return;
      console.error("\n--- Test Log ---");
      for (const e of entries) {
        const ts = new Date(e.time).toISOString().slice(11, 23);
        const dataStr = e.data !== undefined ? ` ${JSON.stringify(e.data)}` : "";
        console.error(`  [${ts}] [${e.source}] ${e.message}${dataStr}`);
      }
      console.error("--- End Log ---\n");
    },
    clear() {
      entries.length = 0;
    },
  };
}
