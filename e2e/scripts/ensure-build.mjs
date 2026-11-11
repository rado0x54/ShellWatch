#!/usr/bin/env node
// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Build what `pnpm test:e2e` runs against: the SvelteKit client into web/dist
// (only when missing or older than client/src — it is the slow part) and the
// server binary into e2e/out/bin/shellwatch (always; `go build` is incremental
// and embeds web/dist). Skip everything with E2E_SKIP_BUILD=1 (CI builds in
// its own steps and points the harness at the binary via E2E_SERVER_BIN).
import { execSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, statSync } from "node:fs";
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

const clientOut = join(root, "web/dist/index.html");
const clientSrc = newest(join(root, "client/src"), [".ts", ".svelte", ".css", ".html"]);
if (!existsSync(clientOut) || statSync(clientOut).mtimeMs < clientSrc) {
  console.log("[e2e] web/dist is missing or stale — running `pnpm build:client`");
  execSync("pnpm build:client", { cwd: root, stdio: "inherit" });
} else {
  console.log("[e2e] web/dist is up to date");
}

const bin = join(root, "e2e/out/bin/shellwatch");
mkdirSync(dirname(bin), { recursive: true });
console.log("[e2e] go build ./cmd/shellwatch");
execSync(`go build -o ${JSON.stringify(bin)} ./cmd/shellwatch`, { cwd: root, stdio: "inherit" });
