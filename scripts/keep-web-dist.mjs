// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Restores web/dist/.gitkeep after a client build.
//
// web/embed.go embeds web/dist with `//go:embed all:dist`, which fails the
// build when the directory holds no file at all — so .gitkeep is tracked
// (.gitignore excepts it) to keep `go build ./...` working in a fresh checkout
// with no client build. But the SvelteKit static adapter wipes its output
// directory, which takes .gitkeep with it; a later `git add -A` then commits
// the deletion and breaks the Go build for everyone.
//
// `pnpm build:client` runs this immediately after vite, so the tracked file is
// always back by the time the build returns. The pre-commit hook additionally
// refuses to stage its deletion, for the case of an interrupted build.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Resolve from this file, not the cwd: the build invokes it from client/.
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(repoRoot, "web", "dist");

mkdirSync(dist, { recursive: true });
writeFileSync(join(dist, ".gitkeep"), "");
