// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden coverage guard — the golden-side analog of the mounted-route/operationId
 * parity check. The original failure mode (#225) was treating "N goldens green"
 * as a proxy for "contract complete"; the golden oracle only covered ~20 of the
 * 54 operationIds, so parity was generalized from a subset. This test makes the
 * gap impossible to hide: it diffs the spec's operationIds against an explicit
 * coverage manifest and fails on ANY operation that is neither goldened nor
 * deliberately excluded (with a stated reason).
 *
 * When you add/remove an operation in docs/api/openapi.yaml, this test fails
 * until you either add a golden and map it here, or add an `excluded` entry
 * documenting why it is not goldened. Exclusions are visible and reviewed —
 * never silent.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";
import { GOLDEN_COVERAGE } from "./golden-coverage.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SPEC = join(HERE, "../../../docs/api/openapi.yaml");
const GOLDENS_DIR = join(HERE, "__goldens__");
const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete"]);

function specOperationIds(): string[] {
  const doc = parseYaml(readFileSync(SPEC, "utf8")) as {
    paths?: Record<string, Record<string, { operationId?: string }>>;
  };
  const ids: string[] = [];
  for (const item of Object.values(doc.paths ?? {})) {
    for (const [method, op] of Object.entries(item)) {
      if (HTTP_METHODS.has(method) && op?.operationId) ids.push(op.operationId);
    }
  }
  return ids;
}

describe("Golden coverage guard", () => {
  const specOps = specOperationIds();

  it("every spec operationId is goldened or explicitly excluded", () => {
    const unaccounted = specOps.filter((op) => !(op in GOLDEN_COVERAGE));
    expect(
      unaccounted,
      `operationIds in openapi.yaml with neither a golden nor an explicit exclusion ` +
        `— add a golden + map it in golden-coverage.ts, or document why it is excluded:\n  ${unaccounted.join("\n  ")}`,
    ).toEqual([]);
  });

  it("the coverage manifest has no stale entries (each maps to a real spec op)", () => {
    const specSet = new Set(specOps);
    const stale = Object.keys(GOLDEN_COVERAGE).filter((op) => !specSet.has(op));
    expect(
      stale,
      `golden-coverage.ts entries not present in openapi.yaml (renamed/removed op?):\n  ${stale.join("\n  ")}`,
    ).toEqual([]);
  });

  it("every mapped golden fixture exists on disk", () => {
    const missing: string[] = [];
    for (const [op, entry] of Object.entries(GOLDEN_COVERAGE)) {
      if ("goldens" in entry) {
        for (const name of entry.goldens) {
          if (!existsSync(join(GOLDENS_DIR, `${name}.json`))) missing.push(`${op} → ${name}.json`);
        }
      }
    }
    expect(
      missing,
      `manifest references golden files that do not exist:\n  ${missing.join("\n  ")}`,
    ).toEqual([]);
  });
});
