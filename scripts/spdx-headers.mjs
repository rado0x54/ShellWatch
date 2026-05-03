#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Walk source files and assert that every one carries an SPDX-License-Identifier
// header matching the path's license (FSL for repo root, MIT for agent-client/).
//
// Modes:
//   --check  (default) — exit 1 listing offenders. Used by CI.
//   --write           — add missing headers, fix mismatches.

import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));

const FSL_ID = "LicenseRef-FSL-1.1-Apache-2.0";
const MIT_ID = "MIT";

function licenseFor(absPath) {
  const rel = relative(repoRoot, absPath);
  if (rel.startsWith("agent-client/")) return MIT_ID;
  return FSL_ID;
}

const COMMENT_STYLES = {
  ".ts": (id) => `// SPDX-License-Identifier: ${id}`,
  ".mts": (id) => `// SPDX-License-Identifier: ${id}`,
  ".js": (id) => `// SPDX-License-Identifier: ${id}`,
  ".mjs": (id) => `// SPDX-License-Identifier: ${id}`,
  ".go": (id) => `// SPDX-License-Identifier: ${id}`,
  ".svelte": (id) => `<!-- SPDX-License-Identifier: ${id} -->`,
  ".html": (id) => `<!-- SPDX-License-Identifier: ${id} -->`,
  ".css": (id) => `/* SPDX-License-Identifier: ${id} */`,
  ".sh": (id) => `# SPDX-License-Identifier: ${id}`,
};

const EXCLUDE_RE = [
  /\/node_modules\//,
  /\/dist\//,
  /\/coverage\//,
  /\/client\/\.svelte-kit\//,
  /\/scripts\/license-overrides\//,
  /\/data\//,
  /\/keys\//,
  /\/logs\//,
  /\/\.git\//,
  /\/\.husky\/_\//, // husky-managed, regenerated on install
  /\/agent-client\/shellwatch-agent(?:-[^/]*)?$/, // built binaries
];

function shouldSkip(absPath) {
  return EXCLUDE_RE.some((re) => re.test(absPath));
}

function commentBuilder(absPath) {
  if (basename(absPath) === "Makefile") return (id) => `# SPDX-License-Identifier: ${id}`;
  return COMMENT_STYLES[extname(absPath)] ?? null;
}

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (shouldSkip(full)) continue;
    const st = statSync(full);
    if (st.isDirectory()) yield* walk(full);
    else yield full;
  }
}

const SPDX_RE = /SPDX-License-Identifier:\s*(\S+)/;

function processFile(absPath, mode) {
  const build = commentBuilder(absPath);
  if (!build) return null;
  const id = licenseFor(absPath);
  const expected = build(id);
  const content = readFileSync(absPath, "utf8");

  const headWindow = content.split("\n").slice(0, 5).join("\n");
  const m = headWindow.match(SPDX_RE);
  if (m) {
    if (m[1] === id) return null; // already correct
    return { path: absPath, status: "wrong", expected: id, actual: m[1] };
  }

  if (mode === "check") return { path: absPath, status: "missing", expected: id };

  // --write: insert header. Preserve shebang as first line; insert above
  // anything else (including Go //go:build constraints — Go allows other line
  // comments before a build constraint as long as the blank line separating
  // it from the package clause stays intact, which it does when prepending).
  let newContent;
  if (content.startsWith("#!")) {
    const nl = content.indexOf("\n");
    if (nl === -1) {
      newContent = content + "\n" + expected + "\n";
    } else {
      newContent = content.slice(0, nl + 1) + expected + "\n" + content.slice(nl + 1);
    }
  } else {
    newContent = expected + "\n" + content;
  }
  writeFileSync(absPath, newContent);
  return { path: absPath, status: "added" };
}

const mode = process.argv.includes("--write") ? "write" : "check";
const results = [];
for (const file of walk(repoRoot)) {
  if (!commentBuilder(file)) continue;
  const r = processFile(file, mode);
  if (r) results.push(r);
}

if (mode === "check") {
  if (results.length === 0) {
    console.log("All source files have correct SPDX-License-Identifier headers.");
    process.exit(0);
  }
  console.error(`SPDX header issues in ${results.length} file(s):\n`);
  for (const r of results) {
    const rel = relative(repoRoot, r.path);
    if (r.status === "missing") {
      console.error(`  missing  ${rel}  -> expected ${r.expected}`);
    } else if (r.status === "wrong") {
      console.error(`  wrong    ${rel}  -> expected ${r.expected}, got ${r.actual}`);
    }
  }
  console.error("\nRun `pnpm spdx:write` to fix automatically.");
  process.exit(1);
} else {
  const added = results.filter((r) => r.status === "added").length;
  const fixed = results.filter((r) => r.status === "wrong").length;
  console.log(`Added SPDX headers to ${added} file(s); flagged ${fixed} mismatched.`);
}
