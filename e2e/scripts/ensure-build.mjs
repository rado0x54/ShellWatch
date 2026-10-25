#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Build dist/ (server + client) when it is missing or older than the sources,
// so `pnpm test:e2e` always runs against the current tree. Skip with
// E2E_SKIP_BUILD=1 (CI builds explicitly in its own step).
import { execSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function newest(dir, exts) {
  let latest = 0;
  const walk = (d) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
      const full = join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (exts.some((e) => entry.name.endsWith(e)))
        latest = Math.max(latest, statSync(full).mtimeMs);
    }
  };
  if (existsSync(dir)) walk(dir);
  return latest;
}

if (process.env.E2E_SKIP_BUILD === "1") process.exit(0);

const serverOut = join(root, "dist/index.js");
const clientOut = join(root, "dist/client/index.html");
const serverSrc = newest(join(root, "src"), [".ts", ".json"]);
const clientSrc = newest(join(root, "client/src"), [".ts", ".svelte", ".css", ".html"]);
const stale =
  !existsSync(serverOut) ||
  !existsSync(clientOut) ||
  statSync(serverOut).mtimeMs < serverSrc ||
  statSync(clientOut).mtimeMs < clientSrc;

if (stale) {
  console.log("[e2e] dist/ is missing or stale — running `pnpm build`");
  execSync("pnpm build", { cwd: root, stdio: "inherit" });
} else {
  console.log("[e2e] dist/ is up to date");
}
