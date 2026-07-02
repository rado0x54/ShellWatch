#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
# Codegen drift gate (#210 Phase 1, supersedes the pre-module smoke check):
# the committed generated code must equal what the pinned generators produce
# from their sources. Runs in CI (api-codegen job) and locally via
# `pnpm api:codegen-check`. Requires a Go toolchain and a clean-ish tree
# (only fails on diffs under the generated paths).
#
#   internal/api        <- oapi-codegen v2.7.1 (docs/api/openapi.yaml)
#   internal/store/gen  <- sqlc v1.31.1 (migrations + queries)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

go generate ./internal/api ./internal/store

if ! git diff --quiet -- internal/api internal/store/gen; then
  echo "ERROR: generated code drifted from its sources." >&2
  echo "Run 'go generate ./internal/api ./internal/store' and commit the result." >&2
  git --no-pager diff --stat -- internal/api internal/store/gen >&2
  exit 1
fi

go build ./internal/api ./internal/store/...
echo "OK: internal/api and internal/store/gen match their sources"
