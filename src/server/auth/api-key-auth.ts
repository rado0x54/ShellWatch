import { createHash } from "node:crypto";

/**
 * SHA-256 hash of a raw API key, matching what the DB stores. Kept here
 * so callers that only need to compute the hash (seeding, the
 * `/api/keys` issuance route, tests) don't need to depend on the full
 * verifier wiring in `./api-key-verifier.ts`.
 */
export function hashApiKey(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}
