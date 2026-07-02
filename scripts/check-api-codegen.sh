#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
# Go-codegen gate for the wire contract (#232 item 3, ahead of #210 Phase 1):
# docs/api/openapi.yaml must stay consumable by the pinned oapi-codegen, and
# the generated Go REST surface must compile. Runs in CI (api-codegen job)
# and locally via `pnpm api:codegen-check`. Requires a Go toolchain.
set -euo pipefail

OAPI_CODEGEN_VERSION="v2.7.1"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/api"
go run "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" \
  -config "$ROOT/docs/api/oapi-codegen.yaml" \
  -o "$TMP/api/api.gen.go" \
  "$ROOT/docs/api/openapi.yaml"

cd "$TMP"
go mod init shellwatch-api-codegen-check >/dev/null 2>&1
go mod tidy >/dev/null 2>&1
go build ./...

OPS="$(grep -c 'operationId:' "$ROOT/docs/api/openapi.yaml")"
echo "OK: oapi-codegen ${OAPI_CODEGEN_VERSION} generated and compiled the REST surface (${OPS} operations)"
