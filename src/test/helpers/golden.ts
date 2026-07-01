// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden / characterization fixtures — the cross-language parity oracle for the
 * Go rewrite (#210, #225 item 2).
 *
 * Each golden captures a real Node-backend response (REST body, WS frame, MCP
 * tool output, audit page) with volatile fields replaced by stable placeholders,
 * committed as JSON under `<testdir>/__goldens__/`. The Go server is expected to
 * replay the same request, apply the SAME normalization (documented below and in
 * docs/api/README.md), and diff against the identical file — so a shape/field/
 * status drift fails loudly in either implementation.
 *
 * Normalization contract (keep in sync with the Go side):
 *   - Keys carrying wall-clock or per-run values → placeholder, regardless of
 *     type: createdAt, updatedAt, lastActivityAt, lastUsedAt, builtAt,
 *     authorizedAt, closedAt, resolvedAt, expiresAt, createdAtEpoch → "<TS>".
 *   - challenge, challengeId, token, stepUpToken → "<REDACTED>".
 *   - nextCursor (when non-null) → "<CURSOR>".
 *   - Value patterns anywhere:
 *       sess_<12 hex>                → "sess_<ID>"
 *       bare UUID v1-5               → "<UUID>"
 *       ISO-8601 timestamp           → "<TS>"
 *       SHA256:<b64> fingerprint     → "<FINGERPRINT>" (test SSH key is per-run)
 *   - Any occurrence of the live server origin (http://127.0.0.1:<port>) in a
 *     string → "<BASE_URL>" (ports are per-run). Discovery docs additionally run
 *     against a pinned externalUrl so their bodies are stable on their own.
 *   - Numeric fields equal to a per-run ephemeral port (ssh/app) → "<PORT>"
 *     (e.g. the seeded endpoint's `port` is the test SSH server's random port).
 *
 * Regenerate all fixtures after an intentional contract change:
 *     UPDATE_GOLDENS=1 pnpm test:integration
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect } from "vitest";

const UPDATE = process.env.UPDATE_GOLDENS === "1";

const TS_KEYS = new Set([
  "createdAt",
  "updatedAt",
  "lastActivityAt",
  "lastUsedAt",
  "builtAt",
  "authorizedAt",
  "closedAt",
  "resolvedAt",
  "expiresAt",
]);
const REDACT_KEYS = new Set(["challenge", "challengeId", "token", "stepUpToken"]);

const SESSION_ID_RE = /^sess_[0-9a-f]{12}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/;
const FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/=]+$/;

export interface NormalizeOptions {
  /** Live server origin(s) to fold to "<BASE_URL>" in string values. */
  baseUrls?: string[];
  /** Per-run ephemeral ports (ssh/app) to fold to "<PORT>" in numeric fields. */
  ports?: number[];
}

function normalizeString(s: string, baseUrls: string[]): string {
  let out = s;
  for (const b of baseUrls) if (b) out = out.split(b).join("<BASE_URL>");
  if (out !== s) return out; // was a URL-bearing string; don't also pattern-swap it
  if (SESSION_ID_RE.test(out)) return "sess_<ID>";
  if (UUID_RE.test(out)) return "<UUID>";
  if (ISO_RE.test(out)) return "<TS>";
  if (FINGERPRINT_RE.test(out)) return "<FINGERPRINT>";
  return out;
}

/** Deep-normalize a captured value into its stable golden form. */
export function normalizeGolden(value: unknown, opts: NormalizeOptions = {}): unknown {
  const baseUrls = opts.baseUrls ?? [];
  const ports = opts.ports ?? [];
  function walk(v: unknown, key?: string): unknown {
    if (key && TS_KEYS.has(key) && v !== null && v !== undefined) return "<TS>";
    if (key && REDACT_KEYS.has(key) && typeof v === "string") return "<REDACTED>";
    if (key === "nextCursor" && typeof v === "string" && v.length > 0) return "<CURSOR>";
    if (typeof v === "number" && ports.includes(v)) return "<PORT>";
    if (typeof v === "string") return normalizeString(v, baseUrls);
    if (Array.isArray(v)) return v.map((item) => walk(item));
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = walk(val, k);
      return out;
    }
    return v;
  }
  return walk(value);
}

/**
 * Assert `actual` matches the committed golden `<testDirOf(metaUrl)>/__goldens__/<name>.json`,
 * after normalization. With `UPDATE_GOLDENS=1` (or when the file is absent) it
 * (re)writes the fixture instead of asserting. Returns the normalized value.
 */
export function expectGolden(
  metaUrl: string,
  name: string,
  actual: unknown,
  opts: NormalizeOptions = {},
): unknown {
  const dir = join(dirname(fileURLToPath(metaUrl)), "__goldens__");
  const file = join(dir, `${name}.json`);
  const normalized = normalizeGolden(actual, opts);
  const serialized = `${JSON.stringify(normalized, null, 2)}\n`;

  if (UPDATE || !existsSync(file)) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(file, serialized);
    return normalized;
  }
  const golden = JSON.parse(readFileSync(file, "utf8"));
  expect(normalized, `golden mismatch for "${name}" (run UPDATE_GOLDENS=1 to refresh)`).toEqual(
    golden,
  );
  return normalized;
}
