// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/** Small async helpers shared by the e2e harness and scenarios. */

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Poll `fn` until it returns a truthy value or the deadline passes. */
export async function waitFor<T>(
  fn: () => Promise<T | null | undefined | false> | T | null | undefined | false,
  opts: { timeoutMs?: number; intervalMs?: number; what?: string } = {},
): Promise<T> {
  const { timeoutMs = 10_000, intervalMs = 100, what = "condition" } = opts;
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  for (;;) {
    try {
      const v = await fn();
      if (v) return v as T;
    } catch (err) {
      lastErr = err;
    }
    if (Date.now() > deadline) {
      throw new Error(
        `Timed out after ${timeoutMs}ms waiting for ${what}` +
          (lastErr ? ` (last error: ${(lastErr as Error).message})` : ""),
      );
    }
    await sleep(intervalMs);
  }
}

/** Standard base64 → base64url (no padding), as a browser would encode the challenge bytes. */
export function b64ToB64url(b64: string): string {
  return Buffer.from(b64, "base64").toString("base64url");
}

/** Strip ANSI escape sequences and CRs so terminal output can be matched as plain text. */
const ESC = String.fromCharCode(0x1b);
const ANSI_CSI = new RegExp(`${ESC}\\[[0-9;?]*[ -/]*[@-~]`, "g");
const ANSI_CHARSET = new RegExp(`${ESC}[()][A-Z0-9]`, "g");
export function stripAnsi(s: string): string {
  return s.replace(ANSI_CSI, "").replace(ANSI_CHARSET, "").replace(/\r/g, "");
}

export function nowIso(): string {
  return new Date().toISOString();
}
