# ShellWatch — Claude Code Instructions

This is the canonical project instructions file for Claude Code working in this repo.

## Project Overview

ShellWatch is a Human-in-the-Loop platform for agent-driven SSH. It's passkey-first and passkey-only — no passwords anywhere — with an SSH-agent proxy that forwards signing requests end-to-end to a user's WebAuthn passkey. Every agent action surfaces in realtime notifications, persists in an append-only audit log, and can be gated behind explicit human approval before it touches the remote host.

Operationally, it brokers terminal sessions between configured SSH targets, human users (via the web UI), and AI agents (via MCP):

- A browser-based terminal UI for interactive SSH sessions
- An MCP (Model Context Protocol) interface for programmatic session control
- A shared terminal Manager that both UI and MCP operate on

## Tech Stack

- **Server:** Go (single binary, `cmd/shellwatch`) — owns all server logic (REST, WebSocket, MCP, SSH, Hydra providers) and embeds the built web UI
- **HTTP:** `net/http` + chi; response models generated from the OpenAPI spec with oapi-codegen (`internal/api`, models only)
- **SSH:** `golang.org/x/crypto/ssh` (client + agent protocol); per-key public-key auth via `ClientConfig.AuthCallback`
- **Persistence:** SQLite (modernc, pure Go) with sqlc-generated queries and goose migrations (`internal/store`)
- **MCP:** official `modelcontextprotocol/go-sdk` (streamable HTTP transport)
- **WebSocket:** `coder/websocket`
- **WebAuthn:** `go-webauthn` for ceremonies; the SSH `webauthn-sk-*` signature format is hand-built in `internal/signing`
- **Auth:** WebAuthn passkeys (human login + SSH signing). OAuth2/OIDC is **fully delegated to Ory Hydra** (web UI, MCP, and agent all use mediated DCR + authorization_code + PKCE); ShellWatch is Hydra's passkey-gated login/consent provider and verifies opaque bearer tokens via introspection. No passwords, no API keys.
- **Config:** YAML (goccy/go-yaml) with hand-rolled validation (`internal/config`)
- **Frontend:** SvelteKit (adapter-static, client-side SPA) with Svelte 5, xterm.js — routing, layouts, and build only; the build output goes to `web/dist` and is embedded by `web/embed.go`
- **Testing:** Go `testing` (unit, in-process integration, golden parity) · Vitest (client unit tests, black-box e2e suite)
- **Linting / formatting:** `gofmt` + `go vet` for Go; ESLint + Prettier for TypeScript/Svelte
- **Package manager (client + e2e tooling):** pnpm
- **Agent client:** Go binary in `agent-client/` (separate module, MIT-licensed)

## Code Conventions

- Go: standard `gofmt` layout, table-driven tests, `fakeClock` instead of sleeps wherever a janitor or TTL exists, no package may import upward (interface → domain → leaf; `cmd/shellwatch` is the only place that knows the whole graph)
- TypeScript (client, e2e): ES modules, destructured imports, strict mode, no `any` unless unavoidable, `.js` extensions in relative imports (Node16 resolution)
- Single-line commit messages with category prefix: `feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, `test:`
- Do not add "Generated with Claude Code" or similar AI attribution to commits or PRs
- **Functions with 5+ parameters must use a typed parameter struct/object** instead of positional args. Export the params type for callers.
- **Every new source file must carry an `SPDX-License-Identifier` header on its first line** (after the shebang, if any). Use `LicenseRef-FSL-1.1-Apache-2.0` for files at the repo root and `MIT` for anything under `agent-client/`. CI enforces this via `pnpm spdx:check`; run `pnpm spdx:write` to add headers to files you've just created. Comment styles by extension: `// …` for `.go`/`.ts`/`.mjs`/`.js`, `<!-- … -->` for `.svelte`/`.html`, `/* … */` for `.css`, `# …` for `.sh`/`Makefile`.
- **Generated code is committed and drift-checked.** After editing `docs/api/openapi.yaml` run `go generate ./internal/api`; after editing `internal/store/queries/*.sql` or a migration run `go generate ./internal/store`. CI (`scripts/check-api-codegen.sh`) fails on drift.
- **Keep the wire contract in sync with the code.** `docs/api/` is the language-agnostic source of truth for every external interface. Whenever you add, remove, or change the shape of an HTTP route (path, method, request/response body, status code), a WebSocket message, or an MCP tool, update the matching artifact in the **same change**: HTTP → [`docs/api/openapi.yaml`](./docs/api/openapi.yaml) (and the golden coverage manifest in `internal/golden/coverage_test.go`); WebSocket → [`docs/api/websocket-protocol.md`](./docs/api/websocket-protocol.md); MCP → [`docs/api/mcp-tools.md`](./docs/api/mcp-tools.md). Document the shape **as-is** (mismatches are catalogued under "Known inconsistencies" in [`docs/api/README.md`](./docs/api/README.md) — don't silently normalize; converge in code + spec together as a deliberate change). Validate with `pnpm api:lint`.
- **Goldens are the regression oracle.** `testdata/goldens/*.json` pin normalized wire responses; the Go suites assert against them and the e2e suite reuses them. A deliberate contract change updates the fixture in the same PR.

## Project Structure

```
cmd/shellwatch/           # Entry point — flags/env, config, wiring, ordered shutdown
internal/
  api/                    # oapi-codegen models (generated from docs/api/openapi.yaml)
  httpserver/, rest/      # chi router + middleware; REST handlers
  ws/                     # Browser WebSocket hub + protocol
  mcp/                    # MCP server, tools, notifier
  agent/                  # AgentSession — per-agent session isolation
  agentproxy/, signagent/ # /agent-proxy bridge; SSH agent protocol server
  terminal/               # Manager, Session, OutputBuffer, Transport interface
  sshx/, signing/         # x/crypto/ssh transport + signers; WebAuthn→SSH signature format
  approval/, push/        # Pending actions, broker, WS + Web Push channels
  webauthn/               # Passkey ceremonies, challenge/step-up/invite stores
  hydra/, auth/           # Hydra providers + admin client + introspection; bearer gate, IP allowlist
  audit/                  # Audit writers and keyset readers
  store/                  # sqlc queries + goose migrations + repositories
  config/, seed/, demo/   # Config schema/loader, first-run seeding, demo endpoints
  golden/                 # Golden normalizer + operationId coverage guard (tests)
  hydratest/, webauthntest/ # Fake Hydra + fake authenticator for Go tests
web/                      # embed.go + dist/ (SvelteKit build output, gitignored)
testdata/goldens/         # Golden wire fixtures shared by Go tests and e2e
e2e/                      # Black-box e2e suite: real sshd + real Hydra in Docker (docs/testing.md)
  harness/                # server launcher, config writer, identity, oauth, sshd control, clients
  lib/                    # fake authenticator, MCP client wrapper, test log, golden normalizer
  scenarios/              # one file = one fresh server
client/                   # SvelteKit frontend app (adapter-static → web/dist)
  src/
    app.html              # HTML shell
    app.css               # Global styles (CSS variables, shared classes)
    service-worker.ts
    lib/
      stores/             # Svelte stores (ws, endpoints, keys, webauthn, auth)
      components/         # Reusable components (Terminal, Sidebar)
      utils/              # Utilities (FIDO signing)
    routes/
      +layout.svelte      # Root layout (sidebar + mobile nav)
      +page.svelte        # Terminal view (default route)
      admin/              # Admin views
      audit/              # Audit log view
      auth/callback/      # OAuth redirect target — exchanges code for tokens
      observer/           # Multi-session grid view
      passkey-invite/     # Passkey invite flow
      register/           # Initial admin registration
      session/            # Session detail
      sign/               # FIDO/SSH signing approval
      settings/           # Settings with tab sub-routes
agent-client/             # Go agent binary (separate module, MIT)
docs/                     # Architecture, deployment, testing, wire contract (docs/api/)
scripts/                  # SPDX check, codegen drift check, license bundling, aaguid refresh
config.sample.yaml        # Sample config
```

## Commands

```bash
# Development
pnpm dev              # go run ./cmd/shellwatch (:3000) + Vite dev server (:3001, proxies API/WS/MCP)
pnpm dev:server       # server only
go run ./cmd/shellwatch -static-dir web/dist   # serve a built client without re-embedding

# Build / run
pnpm build            # client → web/dist, then go build -o shellwatch ./cmd/shellwatch
pnpm build:client     # SvelteKit only
pnpm build:server     # go build only (embeds whatever is in web/dist)
pnpm start            # ./shellwatch (config: arg > $SHELLWATCH_CONFIG > ./config.yaml)

# Server quality gates
go build ./... && go vet ./...
go test ./...         # unit + in-process integration + golden parity + coverage guard
pnpm api:codegen-check  # oapi-codegen / sqlc drift gate

# Client + e2e quality gates
pnpm typecheck        # tsc over e2e/ and scripts/
pnpm check:svelte     # svelte-check
pnpm lint / lint:fix  # ESLint (client + e2e + scripts)
pnpm format / format:check
pnpm test             # client unit tests (Vitest)
pnpm e2e:up           # start the e2e stack (real sshd x2 + real Hydra) in Docker
pnpm test:e2e         # black-box e2e suite against the Go binary (docs/testing.md)
pnpm e2e:down         # tear the e2e stack down

# SPDX headers
pnpm spdx:check       # Verify all source files have SPDX headers (CI gate)
pnpm spdx:write       # Add missing SPDX headers

# API wire contract (docs/api/)
pnpm api:preview      # Redoc HTML from the OpenAPI spec (local, no upload)
pnpm api:lint         # Validate docs/api/openapi.yaml

# Misc
pnpm licenses:bundle  # THIRD_PARTY_LICENSES (client bundle + Go modules)
pnpm update:aaguids   # refresh internal/webauthn/aaguid-names.json
pnpm hydra:migrate    # create/upgrade Hydra's schema in ./data (dev compose)
```

## Architecture

For detailed architecture documentation including data flows, component responsibilities, and planned extensions, see [docs/architecture.md](./docs/architecture.md); the design rationale behind the package layout is in [docs/go-backend-architecture.md](./docs/go-backend-architecture.md).

**Key concepts:**

- **terminal.Manager** — central session registry, source-agnostic. All paths converge here.
- **AgentSession** (`internal/agent`) — session isolation per agent connection. Each agent (MCP or future SSH) only sees its own sessions.
- **Web UI** — sees all of the account's sessions regardless of source via REST API + WebSocket.
- **MCP** — streamable HTTP at `/mcp`. Per-client stateful transport with debounced notifications.
- **Approval broker** (`internal/approval`) — every SSH signature (passkey or file key) is a pending action a human resolves from `/sign/:id`.

```
[Web UI]  [MCP Agent]  [SSH Agent (planned)]
   |          |              |
   |     [AgentSession] [AgentSession]
   |          |              |
   └──────────┼──────────────┘
              |
      [terminal.Manager]
              |
       [sshx transport]
              |
       [Remote host]
```

## Testing

### Philosophy

Three layers: Go tests (unit and in-process integration against a gliderlabs/ssh echo server and a fake Hydra, plus the golden parity fixtures), client unit tests, and a black-box e2e suite against a real OpenSSH `sshd` and a real Ory Hydra. See [docs/testing.md](./docs/testing.md).

### Go tests (`go test ./...`)

- Tests live next to the code (`foo.go` → `foo_test.go`), table-driven, with a fake clock wherever time matters.
- `internal/httpserver` hosts the in-process integration suites: the full handler stack on `httptest`, gliderlabs/ssh as the SSH target (`internal/sshx` tests), `internal/hydratest` as Hydra, `internal/webauthntest` as the passkey.
- Golden parity: `testdata/goldens/*.json` are replayed through `internal/golden.Normalize` and diffed byte-for-byte. `internal/golden/coverage_test.go` fails when an `operationId` in `openapi.yaml` is neither goldened nor explicitly excluded.

### Client unit tests (`pnpm test`)

`client/src/**/*.test.ts` — Svelte stores (ws, endpoints, keys, sessions-api).

### End-to-end tests (black box, `pnpm test:e2e`)

Runs the **built server binary** as a child process against a **real OpenSSH `sshd`** (two images: OpenSSH ≥ 10.3 with `webauthn-sk`, and current Debian stable) and a **real Ory Hydra**, all in Docker (`pnpm e2e:up` / `pnpm e2e:down`). The suite in `e2e/` drives the server only over the wire — REST, `/ws`, `/mcp`, `/agent-proxy` via the Go agent — and imports nothing from the server. Identity is headless: a fake passkey seeded via `seedAdminPasskeys`, then the real authorization-code + PKCE flow through Hydra's redirects. Scenarios: session lifecycle, idle timeout, passkey signing (sshd `Accepted publickey … ECDSA-SK`), skip-identity semantics, agent forwarding (second hop), agent proxy (system `ssh`), MCP, Hydra. Not part of `go test` or `pnpm test`.

### Writing tests

- Go: prefer the in-process harness in `internal/httpserver/*_test.go` for anything crossing a package boundary; assert only what `docs/api/` specifies.
- e2e: one scenario file = one fresh server (`bootScenario`), `recordScenario` for failure dumps, `describe.skipIf(!modernEnabled())` for anything needing `webauthn-sk`.
- Always clean up sessions in `finally` / `t.Cleanup`.

## Config

SSH endpoints are loaded from a YAML config file at startup:

```yaml
seedAdminEndpoints:
  - label: Dev Box
    address: ubuntu@dev.example.com:22
```

Config path is resolved from: CLI arg > `SHELLWATCH_CONFIG` env var > `./config.yaml`. Other env: `HOST` (bind address), `SHELLWATCH_DB` (`sqlite:<path>`), `SHELLWATCH_LOG_LEVEL` / `SHELLWATCH_LOG_FORMAT` / `SHELLWATCH_LOG_FILE`.

## Design Principles

- **Local-first persistence:** SQLite is the only datastore ShellWatch owns — no external/remote database. (OAuth2/OIDC is delegated to Ory Hydra, a required external service; Hydra keeps its own SQLite store, by default in the same `./data` folder.)
- **Single-instance only:** Several stores live in process memory (challenge store, pending-action store, passkey-invite slot). Running ShellWatch behind a load balancer or in cluster mode would silently break those flows. The product is scoped to one process per deployment.
- **Account-scoped:** All operations are scoped to the calling account. Admin is a role, not a cross-account view; never imply cross-account session/output visibility.
- **Shared core:** UI and MCP must use the same Manager — no parallel implementations
- **Real-time sync:** Session changes broadcast to all WebSocket clients immediately
- **Passkey-first:** No passwords, no API keys. WebAuthn passkeys for humans; every client (UI, MCP, agent) authenticates with a Hydra-issued OAuth bearer token whose `sub` is the account.
- **Human-in-the-loop:** Every SSH signature, file key or passkey, is approved by a human; agent actions can require approval before they touch the remote host
- **Simple:** Prefer straightforward code over abstractions. Ship function first, polish later.
