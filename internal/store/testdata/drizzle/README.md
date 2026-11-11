<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# Frozen Node-backend (Drizzle) migration history

Test fixture only. These are the eleven Drizzle migrations the original Node
backend applied to `data/shellwatch.db`, plus its `_journal.json`. The Go
server adopts such a database in place (`store.Migrate` stamps goose's version
table when it finds the Drizzle head, and stamps the Drizzle journal on
Go-created databases so a rollback applies nothing) — see `store.go`
`adoptNodeDatabase` and `migrate_adopt_test.go`, which replays these files to
build a real Node-shaped database. Never edit; the history is closed.
