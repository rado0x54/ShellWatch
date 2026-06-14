#!/usr/bin/env sh
# SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
#
# Explicit Hydra schema migration. NOT run automatically by docker-compose —
# migrations can be destructive (column drops, etc.), so they should be a
# deliberate, backed-up step. This backs up ./data/hydra.sqlite (if present),
# then runs `hydra migrate sql` inside the compose-defined Hydra container so it
# uses the exact same DSN + bind mount as the running service.
#
# Usage:  pnpm hydra:migrate   (run before first `up`, and after any image bump)
set -eu

DB="./data/hydra.sqlite"
# `--profile hydra` so the profiled hydra service is in scope for `run`.
COMPOSE="docker compose --profile hydra"

# Honor a local env file if the operator created one (same as `up`).
if [ -f .env.hydra ]; then
  COMPOSE="docker compose --env-file .env.hydra --profile hydra"
fi

if [ -f "$DB" ]; then
  BAK="$DB.bak-$(date +%Y%m%d-%H%M%S)"
  cp "$DB" "$BAK"
  echo "Backed up $DB -> $BAK"
else
  echo "No existing $DB — creating a fresh schema."
fi

# `run --rm` overrides the service command with the migrate subcommand and
# inherits its environment (DSN) + volumes (./data); `-e` reads DSN from env.
# shellcheck disable=SC2086
$COMPOSE run --rm hydra migrate sql -e --yes

echo "Hydra migrations applied."
