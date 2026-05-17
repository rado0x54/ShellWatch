// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { and, eq, isNotNull, isNull } from "drizzle-orm";
import { fingerprintFromAuthorizedKeys } from "../webauthn/fingerprint.js";
import type { ShellWatchDB } from "./connection.js";
import { webauthnCredentials } from "./schema.js";

export interface BackfillResult {
  /** Rows where fingerprint was filled in by this run. */
  updated: number;
  /** Rows where publicKeyOpenSsh existed but the conversion to a fingerprint failed. */
  skipped: number;
}

/**
 * One-shot data backfill for `webauthn_credentials.fingerprint`. Run once
 * after the DDL migration that introduced the column. Idempotent — selects
 * only rows where fingerprint IS NULL AND publicKeyOpenSsh IS NOT NULL, so
 * re-running it is a no-op for already-fingerprinted credentials.
 *
 * Separate from the seed-from-config path: this exists to retrofit historical
 * rows that pre-date the column. New inserts (credential-store.ts, seed.ts)
 * write the fingerprint at insert time.
 */
export function backfillWebauthnFingerprints(db: ShellWatchDB): BackfillResult {
  const rows = db
    .select({
      id: webauthnCredentials.id,
      publicKeyOpenSsh: webauthnCredentials.publicKeyOpenSsh,
    })
    .from(webauthnCredentials)
    .where(
      and(isNull(webauthnCredentials.fingerprint), isNotNull(webauthnCredentials.publicKeyOpenSsh)),
    )
    .all();

  let updated = 0;
  let skipped = 0;
  for (const row of rows) {
    // Wrap the parser: malformed historical rows (e.g. truncated wire blobs)
    // throw rather than returning null. Treat any failure as "skip and keep
    // NULL fingerprint" — the row wasn't usable for SSH auth anyway.
    let fp: string | null;
    try {
      fp = fingerprintFromAuthorizedKeys(row.publicKeyOpenSsh);
    } catch {
      fp = null;
    }
    if (!fp) {
      skipped++;
      continue;
    }
    db.update(webauthnCredentials)
      .set({ fingerprint: fp })
      .where(eq(webauthnCredentials.id, row.id))
      .run();
    updated++;
  }

  return { updated, skipped };
}
