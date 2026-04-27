import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface BuildInfo {
  /** Full git SHA, or "dev" when running locally without a generated build file. */
  sha: string;
  /** Branch or ref name (e.g. "develop", "main"), or "local" for ungenerated builds. */
  ref: string;
  /** Release tag (e.g. "v0.4.2") if the build was produced from a tagged ref. */
  tag: string | null;
  /** ISO-8601 build timestamp, or null for ungenerated builds. */
  builtAt: string | null;
  /** Human-readable identifier: tag if available, else `${ref}@${shortSha}`. */
  display: string;
}

const FALLBACK: Omit<BuildInfo, "display"> = {
  sha: "dev",
  ref: "local",
  tag: null,
  builtAt: null,
};

export function deriveDisplay(sha: string, ref: string, tag: string | null): string {
  if (tag) return tag;
  const shortSha = sha.slice(0, 7);
  return `${ref}@${shortSha}`;
}

export function loadBuildInfo(searchDir?: string): BuildInfo {
  // Default: resolve relative to this module so the lookup is stable regardless
  // of cwd. With rootDir=src / outDir=dist the layout mirrors source: in dev
  // src/server/buildInfo.ts, in prod dist/server/buildInfo.js — both two
  // levels above the repo/app root where buildInfo.generated.json lives.
  const dir = searchDir ?? fileURLToPath(new URL("../..", import.meta.url));
  const candidate = resolve(dir, "buildInfo.generated.json");
  try {
    const raw = readFileSync(candidate, "utf8");
    const parsed = JSON.parse(raw) as Partial<typeof FALLBACK>;
    const sha = parsed.sha ?? FALLBACK.sha;
    const ref = parsed.ref ?? FALLBACK.ref;
    const tag = parsed.tag ?? null;
    const builtAt = parsed.builtAt ?? null;
    return { sha, ref, tag, builtAt, display: deriveDisplay(sha, ref, tag) };
  } catch {
    return {
      ...FALLBACK,
      display: deriveDisplay(FALLBACK.sha, FALLBACK.ref, FALLBACK.tag),
    };
  }
}

export const buildInfo: BuildInfo = loadBuildInfo();
