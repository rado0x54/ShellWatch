#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Copy the variable woff2 files and OFL license shipped by
// @fontsource-variable/geist and @fontsource-variable/geist-mono into
// client/static/fonts/. The committed files under client/static/fonts/ are
// the source of truth at runtime; the npm packages are devDeps that exist
// only to feed this script. Run after bumping either fontsource version,
// then commit the changes.

import { copyFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const destDir = join(repoRoot, "client", "static", "fonts");
mkdirSync(destDir, { recursive: true });

const sources = [
  join(repoRoot, "node_modules", "@fontsource-variable", "geist"),
  join(repoRoot, "node_modules", "@fontsource-variable", "geist-mono"),
];

for (const pkgDir of sources) {
  const filesDir = join(pkgDir, "files");
  for (const file of readdirSync(filesDir)) {
    if (!file.endsWith("-wght-normal.woff2")) continue;
    copyFileSync(join(filesDir, file), join(destDir, file));
    console.log(`copied ${file}`);
  }
}

// Both packages ship the same OFL-1.1 text (Vercel-authored Geist family);
// copy from the first source so the license travels with the woff2 files.
copyFileSync(join(sources[0], "LICENSE"), join(destDir, "OFL.txt"));
console.log("copied OFL.txt");
