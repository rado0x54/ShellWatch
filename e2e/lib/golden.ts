// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden normalization — the e2e side of the parity oracle (#225 item 2).
 *
 * Each golden under `testdata/goldens/` captures one wire response (REST body,
 * WS frame, MCP tool output, audit page) with volatile fields replaced by
 * stable placeholders. The server's own suites (`internal/golden`,
 * `internal/httpserver`) replay the same requests and diff against the same
 * files; the e2e suite applies the same normalization when it compares a live
 * response to a committed fixture (discovery documents in hydra.e2e.test.ts).
 *
 * Normalization contract (keep in sync with internal/golden/golden.go):
 *   - Keys carrying wall-clock or per-run values → placeholder, regardless of
 *     type (ISO string or epoch-ms/epoch-s number): createdAt, updatedAt,
 *     lastActivityAt, lastUsedAt, builtAt, authorizedAt, closedAt, resolvedAt,
 *     expiresAt, client_id_issued_at → "<TS>".
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
 *   - A `port` field whose value is a per-run ephemeral port (ssh/app) → "<PORT>"
 *     (the seeded endpoint's `port` is the test SSH server's random port). Scoped
 *     to the `port` key so unrelated numbers can't be masked by coincidence.
 *
 */

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
  // DCR (RFC 7591): epoch-SECONDS number, not ISO — folded by key, not pattern.
  "client_id_issued_at",
]);
const REDACT_KEYS = new Set(["challenge", "challengeId", "token", "stepUpToken"]);

const SESSION_ID_RE = /^sess_[0-9a-f]{12}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/;
const FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/=]+$/;

export interface NormalizeOptions {
  /** Live server origin(s) to fold to "<BASE_URL>" in string values. */
  baseUrls?: string[];
  /** Per-run ephemeral ports (ssh/app) to fold to "<PORT>" in a `port` field. */
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
    // Scoped to `port` on purpose: a bare `ports.includes(v)` is key-agnostic and
    // would mask any numeric field that happened to equal an ephemeral port.
    if (key === "port" && typeof v === "number" && ports.includes(v)) return "<PORT>";
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
