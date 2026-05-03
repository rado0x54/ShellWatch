// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export interface BuildInfo {
  /** Full git SHA, or "dev" when running locally without a generated build file. */
  sha: string;
  /** Branch or ref name (e.g. "develop", "main"), or "local" for ungenerated builds. */
  ref: string;
  /**
   * Release tag (e.g. "v0.4.2"), set via GIT_TAG env at retag time
   * (`crane mutate --set-env GIT_TAG=...`). Never written into the JSON file.
   */
  tag: string | null;
  /** ISO-8601 build timestamp, or null for ungenerated builds. */
  builtAt: string | null;
  /** Human-readable identifier: tag if available, else `${ref}@${shortSha}`. */
  display: string;
}

interface PersistedBuildInfo {
  sha: string;
  ref: string;
  builtAt: string | null;
}

const FALLBACK: PersistedBuildInfo = {
  sha: "dev",
  ref: "local",
  builtAt: null,
};

export function deriveDisplay(sha: string, ref: string, tag: string | null): string {
  if (tag) return tag;
  const shortSha = sha.slice(0, 7);
  return `${ref}@${shortSha}`;
}

export function loadBuildInfo(cwd: string = process.cwd()): BuildInfo {
  const candidate = resolve(cwd, "buildInfo.generated.json");
  let sha = FALLBACK.sha;
  let ref = FALLBACK.ref;
  let builtAt: string | null = FALLBACK.builtAt;
  try {
    const parsed = JSON.parse(readFileSync(candidate, "utf8")) as Partial<PersistedBuildInfo>;
    // `||` not `??` — treat empty strings as missing too, in case CI ever
    // writes `ref: ""` (otherwise display becomes "@abcdef1").
    sha = parsed.sha || FALLBACK.sha;
    ref = parsed.ref || FALLBACK.ref;
    builtAt = parsed.builtAt ?? null;
  } catch {
    /* keep fallbacks */
  }
  const tag = process.env.GIT_TAG || null;
  return { sha, ref, tag, builtAt, display: deriveDisplay(sha, ref, tag) };
}

export const buildInfo: BuildInfo = loadBuildInfo();
