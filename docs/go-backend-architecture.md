<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# Go Backend — Architecture Specification

Design specification for the Go rewrite of the ShellWatch backend ([#210]).
This document does two things:

1. **Freezes the dependency decisions** — every "or"-row in #210's mapping
   table is narrowed to a single winner, with rationale and rejected
   alternatives (§2).
2. **Specifies the target architecture** — the Node backend grew
   progressively; the rewrite is the one chance to fix its accidental
   complexity without breaking the wire contract. §4–§6 define what we keep,
   what we deliberately redesign, and why.

**Status:** accepted design, implementation not yet scheduled (see #210).
**Acceptance gate:** the frozen wire contract in [`docs/api/`](./api/README.md)
plus the golden parity fixtures from #225. Parity first, convergence second
(§7).

Verified against the library ecosystem as of **July 2026**.

---

## 1. Scope and invariants

### In scope

Everything under `src/` — the Fastify server, terminal core, SSH transport,
WebAuthn/signing, Hydra glue, pending actions, audit, persistence.

### Explicitly unchanged (non-goals)

| Invariant                                                                            | Consequence                                                                                                                                 |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **Wire contract** (`docs/api/openapi.yaml`, `websocket-protocol.md`, `mcp-tools.md`) | Go handlers reproduce responses byte-for-byte modulo the documented normalization; the A–J inconsistencies are _preserved_ in the port (§7) |
| **SvelteKit frontend**                                                               | Ships unchanged; the Go server serves the same static build (now embedded, §5.11)                                                           |
| **SQLite schema**                                                                    | Tables, columns, CHECK constraints, and indexes carry over as-is; only the migration _tool_ changes                                         |
| **OAuth delegation to Ory Hydra**                                                    | Go backend remains Hydra's passkey login/consent provider + introspection client — a faithful port of `src/hydra/`, not a redesign          |
| **Single-instance process model**                                                    | Ephemeral state stays in memory by design; we make the constraint _visible_ (one `ephemeral` package) rather than removing it               |
| **Account scoping model**                                                            | Admin is a role, not a cross-account view; scoping moves _down_ into the store layer (§5.6) but semantics are identical                     |
| **`agent-client/`**                                                                  | Already Go; untouched (one optional follow-up in §2, WebSocket row)                                                                         |

---

## 2. Dependency decisions — single winners

Every row is final. "Rejected" lists what #210 still had as alternatives and
why they lost. Maintenance status verified July 2026.

| Concern                                          | Winner                                                                                                                        | Rejected                                          | Why                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| HTTP router                                      | **`go-chi/chi` v5**                                                                                                           | echo, bare `net/http`                             | 100% `net/http`-compatible (a chi router _is_ an `http.Handler`), so stdlib middleware and oapi-codegen validation work unchanged; subrouters/route groups fit the API+WS+MCP+Hydra surface; zero lock-in — dropping to stdlib later is trivial. Echo brings a foreign context type for no gain. Actively maintained (v5.3.0, 2026-05).                                                                                                                      |
| REST surface                                     | **`oapi-codegen` v2, strict-server mode, chi target**                                                                         | hand-written routes                               | Generated request/response types + handler interface from the frozen `openapi.yaml`; contract drift becomes a compile error. Spec-validation middleware via `oapi-codegen/nethttp-middleware` (kin-openapi). Committed generated code + `go generate` + CI diff (§5.5). Healthy (v2.7.1, 2026-06).                                                                                                                                                           |
| WebSocket                                        | **`coder/websocket`**                                                                                                         | gorilla/websocket, gobwas/ws                      | The only actively maintained option (v1.8.15, 2026-06). gorilla was revived in 2023 and has gone dormant _again_ (last release 2024-06, last push 2025-03). gobwas targets million-connection zero-copy servers — wrong tradeoff. coder's context-aware, concurrency-safe API fits our handler model. _Note:_ `agent-client/` uses gorilla today; it keeps working, but migrating it to coder/websocket is a cheap follow-up for one-dependency consistency. |
| SSH client                                       | **`golang.org/x/crypto/ssh`**                                                                                                 | — (already decided in #210)                       | Full OpenSSH cert support (`Certificate`, `NewCertSigner`, `CertChecker`); custom `ssh.Signer` carries the webauthn-sk-\* `Rest` payload verbatim — no fork. Kills the `rado0x54/ssh2#shellwatch` fork permanently. 2026 releases added parallel agent-signing pipelining (directly useful for the agent proxy).                                                                                                                                             |
| SSH agent protocol (server side, `/agent-proxy`) | **`golang.org/x/crypto/ssh/agent`** (`agent.ServeAgent` over a WS-framed `io.ReadWriter`; we implement `agent.ExtendedAgent`) | hand-rolled protocol                              | Replaces the ssh2 fork's `AgentProtocol`. Same module as the SSH client — no new dependency.                                                                                                                                                                                                                                                                                                                                                                 |
| MCP server                                       | **`github.com/modelcontextprotocol/go-sdk`** ≥ v1.6                                                                           | —                                                 | Official SDK, stable since v1.0 with a no-breaking-changes guarantee (v1.6.1, 2026-05). Streamable-HTTP server transport, per-connection `ServerSession` state, server→client notifications — everything `/mcp` needs. Known wrinkle: strict Content-Type validation (escape hatch exists); validate against the MCP goldens early.                                                                                                                          |
| SQLite driver                                    | **`modernc.org/sqlite`** (pure Go)                                                                                            | mattn/go-sqlite3 (cgo), ncruces/go-sqlite3 (wasm) | Static single binary + painless cross-compilation is the whole point of the rewrite's ops story; cgo kills both. PocketBase's default driver — battle-tested at exactly our scale. ncruces is credible but v0.x and adds a wazero runtime. Benchmarks show no meaningful perf gap at our load.                                                                                                                                                               |
| DB layer                                         | **`sqlc`**                                                                                                                    | ent, sqlx, bare `database/sql`                    | ~8 tables, simple queries: sqlc generates fully typed Go from plain SQL with zero runtime dependency; the `.sql` files double as documentation of the persistence contract. ent is graph-ORM overkill; sqlx keeps hand-written scan targets. Active (v1.31.1, 2026-04).                                                                                                                                                                                      |
| Migrations                                       | **`pressly/goose`** (embedded via `go:embed`, run at startup)                                                                 | golang-migrate/migrate                            | Library-first API (`goose.SetBaseFS` + `goose.Up`) matches "auto-run at startup" exactly; supports Go-function migrations for future data backfills; more actively maintained (v3.27.2, 2026-06 vs migrate 2025-11). migrate's strength (many DBs, CLI) is irrelevant for one embedded SQLite file.                                                                                                                                                          |
| WebAuthn                                         | **`github.com/go-webauthn/webauthn`**                                                                                         | —                                                 | Mature (used by Teleport), active (v0.17.4, 2026-05). The `protocol` package exposes raw authenticator data + COSE keys, which we need for OpenSSH `webauthn-sk-*` key derivation; `SessionData` is a plain struct so our own challenge store works. Still v0.x — pin and review changelogs.                                                                                                                                                                 |
| Web Push                                         | **`SherClockHolmes/webpush-go`**                                                                                              | — (missing from #210's table)                     | De-facto standard VAPID/Web-Push library. Small, replaceable behind the `NotificationChannel` seam if it ever stalls. Re-verify maintenance at implementation time.                                                                                                                                                                                                                                                                                          |
| YAML                                             | **`goccy/go-yaml`**                                                                                                           | ~~`gopkg.in/yaml.v3`~~                            | **Correction to #210:** `go-yaml/yaml` (yaml.v3) was archived in 2025 and is unmaintained. goccy/go-yaml is the actively maintained successor the ecosystem converged on.                                                                                                                                                                                                                                                                                    |
| Config validation                                | **hand-rolled validation in `internal/config`**                                                                               | go-playground/validator                           | The schema is small and zod's refinements (cross-field rules, defaults, custom messages) don't map to struct tags anyway. Plain Go `Validate()` methods are more readable than tag DSLs, cost zero dependencies, and validator's maintainer bandwidth is openly thin.                                                                                                                                                                                        |
| Logging                                          | **`log/slog`** (stdlib)                                                                                                       | zap, zerolog                                      | Settled 2026 consensus for new services. Structured, leveled, zero deps.                                                                                                                                                                                                                                                                                                                                                                                     |
| Testing                                          | **stdlib `testing` + `stretchr/testify` v1**                                                                                  | —                                                 | testify v1 remains the standard (explicitly no v2).                                                                                                                                                                                                                                                                                                                                                                                                          |
| In-process SSH server (tests only)               | **`gliderlabs/ssh`**                                                                                                          | raw `x/crypto/ssh` server                         | Dormant (last release 2024-12) but stable, test-only, and saves ~200 lines of channel/PTY boilerplate per scenario. Tailscale and Charm maintain derivatives we could vendor from if a CVE ever surfaces. Eyes open, acceptable for a dev dependency.                                                                                                                                                                                                        |
| Hydra admin client                               | **hand-written on `net/http`**                                                                                                | ory/hydra-client-go                               | The Node `admin-client.ts` is a thin typed wrapper over ~12 admin endpoints; a generated Ory SDK drags in a huge OpenAPI client for no benefit. Port the thin wrapper.                                                                                                                                                                                                                                                                                       |
| Static frontend                                  | **`go:embed` of the SvelteKit build**                                                                                         | filesystem serving                                | One self-contained binary — the deploy story #210 promises. A `-static-dir` flag keeps the dev override.                                                                                                                                                                                                                                                                                                                                                     |

**Go toolchain:** latest stable at implementation start (Go 1.26 as of this
writing). `agent-client/` (currently Go 1.24) is bumped independently.

---

## 3. Current architecture — what the rewrite must answer for

A code-level inventory of `src/` (July 2026) surfaced the structural debts
below. Each maps to a design response in §5; this table is the "critically
question the architecture" record the rewrite is built on.

| #   | Debt in the Node backend                                                                                                                     | Go design response                                                                                                                                                                |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| W1  | `transport/create-factory.ts` is a hidden god-function where terminal, SSH, WebAuthn, approvals, and DB meet via four sign-callback closures | Explicit `signing.Broker` interface owned by the `approval` domain; transports depend on the interface, wiring lives only in `cmd/shellwatch` (§5.8)                              |
| W2  | `pending-action` ⇄ `webauthn` circular dependency (types one way, runtime the other)                                                         | Sign-request vocabulary moves to a leaf package `internal/signing` (pure types + wire-format functions); both `approval` and `sshx` depend downward on it (§5.8)                  |
| W3  | Two parallel WS connection registries (`ws-handler` + `WebSocketChannel`) bridged by the `WsExtension` indirection                           | One `ws.Hub` owning all browser sockets, account-indexed; the approval layer sends through a narrow `Notifier` interface (§5.7)                                                   |
| W4  | Module-level singleton stores (challenge, step-up, invite) with `_reset*` test hooks, unlike the class-based stores                          | One generic `ephemeral.Store[K,V]` (TTL, cap, single-use consume, injectable clock); all four ephemeral maps become instances wired in main (§5.4)                                |
| W5  | Seven independent ad-hoc timers (`unref()`'d sweeps, debounces, flushes)                                                                     | Each component runs a context-cancelled janitor goroutine on an injected `clock.Clock`; tests drive a fake clock — no sleeps, no reset hooks (§5.4)                               |
| W6  | `OutputBuffer` is JS-string (UTF-16 char) based; offsets are string lengths; mid-rune and mid-ANSI-escape splits are patched heuristically   | Byte-oriented ring buffer with monotonic byte offsets (§5.3; parity note in §7, item K)                                                                                           |
| W7  | Cosmetic-async repositories over synchronous better-sqlite3; DB writes on the auth hot path disguised as awaits                              | Honest synchronous store calls with `context.Context`; the last-used batching becomes an explicit write-behind flusher (§5.6)                                                     |
| W8  | `webauthn_credentials` has no single owner — raw Drizzle in six webauthn files + routes + cleanup, _plus_ a repository                       | One sqlc-backed `store.Credentials` type; nothing else touches the table (§5.6)                                                                                                   |
| W9  | Only one real transaction in the codebase; multi-statement account deletion/cleanup can be interrupted half-done                             | Store layer exposes `WithTx`; account deletion and cleanup are transactional by construction (§5.6)                                                                               |
| W10 | Un-debounced WS fan-out: every status change re-serializes the session list per client; every output chunk forwarded immediately             | Output fan-out becomes coalesced wake-ups + read-since-offset (§5.2); status events stay per-event (low frequency, parity-relevant ordering)                                      |
| W11 | DI root has late-binding mutable boxes (`agentLog.current`), forward-referenced closures, and an order-dependent shutdown commented as such  | `cmd/shellwatch` wires a DAG of constructors; shutdown is an explicit reverse-order `Close` list — the ordering constraint (audit writers close last) is code, not comment (§5.1) |
| W12 | `request.apiKey` carries an OAuth principal (API keys were removed in migration 0009)                                                        | `auth.Principal{AccountID, Scopes}` in the request context; no legacy names (§5.9)                                                                                                |
| W13 | Account scoping enforced ad hoc in every handler                                                                                             | Every sqlc query on account-owned tables takes `account_id` in its WHERE clause — unscoped access doesn't compile (§5.6); handlers keep the 404-not-403 convention                |
| W14 | `util/` vs `utils/` split (one file each)                                                                                                    | n/a — Go layout has no equivalent seam (§5.0)                                                                                                                                     |
| W15 | Docs promise Slack/webhook notification channels that don't exist                                                                            | Spec'd honestly: `approval.Channel` is the seam, WS + Push are the implementations, Slack/Telegram are future work (§5.8)                                                         |

Also inherited knowingly: the `ssh` terminal source (#12) stays half-plumbed
(enum value + reserved audit columns, no implementation), and the
`NotificationChannel`/`Channel` seam stays open for it.

---

## 4. Target architecture — overview

The component _concepts_ survive (they are good): TerminalManager,
TerminalTransport, OutputBuffer, AgentSession, PendingAction store,
NotificationDispatcher, bearer gate, audit writers. What changes is the
_wiring discipline_: dependencies form a DAG, ephemeral state is uniform and
injectable, fan-out is explicit, and the composition root is the only place
that knows the whole graph.

```
                    cmd/shellwatch (composition root)
                                 │ wires everything; owns shutdown order
   ┌──────────┬──────────┬──────┴────┬───────────┬──────────┐
   │httpserver│    ws    │    mcp    │agentproxy │  hydra    │   interface layer
   │(chi+gen) │  (hub)   │ (go-sdk)  │(ssh agent)│(providers)│
   └────┬─────┴────┬─────┴─────┬─────┴─────┬─────┴────┬──────┘
        │          │           │           │          │
        │     ┌────┴───────────┴─────┐  ┌──┴───────┐  │
        │     │ terminal (Manager,   │  │ approval │  │          domain layer
        │     │ Session, OutputBuf,  │  │ (actions,│  │
        │     │ AgentSession)        │  │ channels)│  │
        │     └────┬─────────────────┘  └──┬───────┘  │
        │          │                       │          │
        │     ┌────┴────┐             ┌────┴─────┐    │
        │     │  sshx   │────────────▶│ signing  │    │          leaf domain
        │     │(x/crypto│  SignReq    │(types +  │    │
        │     │ client, │  interface  │ wire fmt)│    │
        │     │ signers)│             └──────────┘    │
        │     └─────────┘                             │
   ┌────┴─────────────────────────────────────────────┴──────┐
   │ store (sqlc+goose) · webauthn (ceremonies) · audit ·     │  foundation
   │ auth (gate) · config · ephemeral · clock · buildinfo     │
   └──────────────────────────────────────────────────────────┘
```

Arrows point downward only. The two cycles in the Node graph (W1, W2) are
resolved by the leaf `signing` package and by moving all cross-domain wiring
into `cmd/shellwatch`.

### Package layout

```
go.mod                          # module github.com/rado0x54/shellwatch (repo root)
cmd/shellwatch/main.go          # flags/env → config → wire → run → ordered shutdown
internal/
  api/                          # oapi-codegen output (generated; committed)
  httpserver/                   # chi router, middleware stack, StrictServerInterface impl
  ws/                           # browser WS: hub, protocol types, message router
  mcp/                          # MCP server, tools, per-session notifier (debounce)
  agentproxy/                   # /agent-proxy: WS framing ↔ agent.ServeAgent
  terminal/                     # Manager, Session, OutputBuffer, Transport iface, AgentSession, keymap
  sshx/                         # x/crypto/ssh transport, webauthn/cert/file signers,
                                #   composite agent, key scanner + directory watcher
  signing/                      # leaf: SignRequest types, WebAuthn→SSH sig format,
                                #   COSE→OpenSSH key derivation (pure functions)
  approval/                     # PendingAction store, dispatcher, ws/push channels
  webauthn/                     # ceremony orchestration (go-webauthn), challenge store,
                                #   step-up, invite slot (all on ephemeral.Store)
  hydra/                        # admin client, bearer resolver, login/consent/logout
                                #   providers, mediated DCR, discovery docs
  auth/                         # bearer gate middleware, scope routing, IP allowlist,
                                #   step-up gate, Principal
  audit/                        # lifecycle + signing writers (guaranteed subscribers), readers
  store/                        # sqlc queries + migrations/ (goose, embedded), WithTx
  config/                       # goccy/go-yaml load + hand-rolled Validate()
  ephemeral/                    # generic TTL store (W4)
  clock/                        # Clock interface + real/fake
web/embed.go                    # go:embed of the SvelteKit build output
```

The Go module lives at the **repo root** (`src/` remains the Node tree until
cutover; Go tooling ignores it). `agent-client/` stays its own module.

---

## 5. Component specifications

### 5.0 Conventions

- Every package exposes interfaces for what it _consumes_ and concrete types
  for what it _provides_; interfaces are defined consumer-side (Go idiom).
- All blocking operations take `context.Context`; all long-lived goroutines
  are tied to a context from `main` and exit on cancellation.
- `slog` with component-scoped loggers (`slog.With("component", "terminal")`).
- SPDX headers per repo policy (`LicenseRef-FSL-1.1-Apache-2.0` at root).
- No package-level mutable state anywhere (W4/W14 die by convention).

### 5.1 Composition root and lifecycle (`cmd/shellwatch`)

`main` is the only place that sees the whole graph:

1. Parse flags/env → `config.Load` → `config.Validate` (fail fast).
2. Open SQLite (`modernc.org/sqlite`, WAL, foreign_keys=ON) → `goose.Up`.
3. Construct foundation (clock, stores, ephemeral instances), then domains
   (signing broker, approval, terminal manager, sshx factory), then interface
   layer (hub, MCP, agent proxy, hydra providers, chi router).
4. `ensureSpaClient` against Hydra (fail fast if unreachable — as today).
5. Serve; on SIGINT/SIGTERM cancel the root context and run an explicit
   reverse-order close list. The Node shutdown's fragile comment-enforced
   ordering (terminals before lifecycle writer, action store before signing
   writer) becomes a literal slice of `io.Closer`s executed in order (W11).

No mutable late-binding: the MCP client-info that Node injects via the
`agentLog.current` box becomes a value carried on the session-create call
path (§5.10).

### 5.2 Terminal core (`internal/terminal`)

`Manager` is a mutex-guarded registry (`map[sessionID]*Session`); each
`Session` owns one pump goroutine that reads transport data, appends to its
`OutputBuffer`, and notifies subscribers. Two subscription kinds, replacing
the single lossy-by-luck EventEmitter bus:

- **Guaranteed hooks** (audit): synchronous, ordered callbacks invoked on
  status transitions. Audit cannot miss events; failures are logged and
  swallowed (audit must never break a session — same policy as today).
- **Coalesced watchers** (WS hub, MCP notifier): per-subscriber
  `chan struct{}` with capacity 1. A burst of output collapses into one
  wake-up; the consumer reads from the buffer since its last offset. This
  replaces both the un-debounced Node WS forwarding (W10) _and_ the
  hand-rolled MCP timer debounce with one mechanism. The MCP notifier keeps
  its configurable `debounceMs` on top (sleep-after-wake on the fake-able
  clock) to preserve today's pacing.

**Status changes are not coalesced** — they are low-frequency and their
ordering (`opening → open → closed`) is observable in the WS goldens.

Idle cleanup: one janitor goroutine per Manager (60s tick, 30min idle close),
on the injected clock.

`AgentSession` ports as-is: ownership set, scoped create/list/read/close,
`Destroy` closing owned sessions. MCP gets one per `ServerSession`.

### 5.3 OutputBuffer — bytes, not strings (W6)

Append-only **byte** ring with a monotonic base offset; eviction trims whole
appended chunks from the head (as today), `ReadAfter(offset)` returns
`(data []byte, nextOffset int64, reset bool)`. UTF-8 decoding happens at the
edges that need text (JSON frames), not in the buffer. The Node tail
heuristic for mid-escape truncation is reimplemented on bytes.

This changes offset _arithmetic_ for multi-byte output (see §7 item K for the
parity ruling). Capacity stays 1 MiB.

### 5.4 Ephemeral state (`internal/ephemeral`, `internal/clock`) (W4, W5)

One generic store covers every in-memory TTL map in the system:

```go
type Store[K comparable, V any] struct { /* mutex, map, ttl, cap, clock */ }
func (s *Store[K, V]) Put(k K, v V)                 // evict-oldest at cap
func (s *Store[K, V]) Consume(k K) (V, bool)        // single-use get+delete
func (s *Store[K, V]) Get(k K) (V, bool)
func (s *Store[K, V]) Janitor(ctx context.Context)  // periodic sweep
```

Instances (all wired in main, all on the shared fake-able clock):
WebAuthn challenges (5 min, cap 10 000), step-up tokens (90 s, single-use,
action+account-bound), passkey-invite slot (5 min, keyed by account,
supersede semantics preserved), bearer introspection cache (60 s,
positive-only, cap 2048). The pending-action store (§5.8) is its own type —
it has richer state transitions — but uses the same clock/janitor pattern.

This kills every module-level singleton, every `_reset*` test hook, and every
free-running timer in the Node backend. The single-instance deployment
constraint is now one greppable package.

### 5.5 REST surface (`internal/api`, `internal/httpserver`)

- `internal/api` is generated by oapi-codegen v2 (strict-server, chi) from
  `docs/api/openapi.yaml`; output is committed; `go generate ./...` + a CI
  diff step is the Go-side `pnpm api:lint` — spec drift fails the build.
- `internal/httpserver` implements the generated `StrictServerInterface`,
  translating to domain calls. Handler bodies are hand-written; shapes are
  generated. Loosely-modeled bodies (WebAuthn ceremony envelopes,
  `credential: {}`) stay `map[string]any` passthroughs by design.
- Middleware stack (chi): request-ID → slog access log → IP allowlist (path-
  scoped, `/mcp`) → bearer gate (§5.9) → kin-openapi request validation →
  handlers. `/ws`, `/mcp`, `/agent-proxy`, Hydra provider pages, and static
  files mount beside the generated router on the same chi mux.
- **Error envelopes:** one internal error type
  `apierr.E{Status int, Code string, Msg string}` renders today's three wire
  shapes (`{error}`, `{error, code}` for step-up, `{error, error_description}`
  for DCR) via per-surface renderers. Parity now; flipping everything to
  `{error, code}` later (contract item F) is a renderer change, not a hunt
  through handlers.

### 5.6 Persistence (`internal/store`) (W7–W9, W13)

- Schema carried over verbatim; goose migrations embedded and run at startup.
  Migration 0001 recreates the current schema; a documented import path
  copies an existing `shellwatch.db` (schema-identical, so cutover is
  file-copy + goose version stamp).
- sqlc generates the query layer from `.sql` files; thin store types
  (`store.Accounts`, `store.Endpoints`, `store.Credentials`,
  `store.SSHKeys`, `store.AuditLifecycle`, `store.AuditSignings`,
  `store.PushSubs`) wrap them. **`store.Credentials` is the only owner of
  `webauthn_credentials`** (W8).
- **Every query on account-owned tables takes `account_id`** in SQL (W13).
  The 404-not-403 disclosure convention stays in handlers, but a handler
  _cannot_ forget scoping — the generated function signature demands it.
- `store.WithTx(ctx, fn)` wraps `database/sql` transactions. Account
  deletion (route + inactive-account cleanup) is transactional (W9).
- Synchronous, honest API — no cosmetic async (W7). `database/sql` pooling:
  a single writer connection (SQLite) + WAL readers; the last-used
  touch keeps its Node batching semantics as an explicit write-behind map
  flushed by a janitor (60 s), so the auth hot path never writes.

### 5.7 Browser WebSocket (`internal/ws`) (W3, W10)

One `Hub` owns every browser socket with its metadata (account, attached
sessions, controlled sessions) — the Node split between `ws-handler` and
`WebSocketChannel` collapses into it:

- Terminal protocol: same message set as `websocket-protocol.md`
  (attach/input/resize/close/take-control/release-control in;
  output/status/closed/mode/sessions:changed/error out). Output delivery is
  watcher-based read-since-offset (§5.2); message shapes unchanged.
- Account-scoped sends: `Hub.SendToAccount(accountID, msg)` — the approval
  layer's WS channel (§5.8) uses this narrow interface instead of tracking
  sockets itself. The `WsExtension` indirection has no Go equivalent.
- Per-connection writer goroutine + bounded outbound queue (coder/websocket
  is concurrency-safe, but ordering per connection must be preserved);
  slow-client policy: drop the connection, never block the hub.
- Bearer via `Sec-WebSocket-Protocol: shellwatch.bearer, <token>` exactly as
  today (sentinel subprotocol negotiated, token never echoed).

### 5.8 Signing and approvals (`internal/signing`, `internal/approval`) (W1, W2, W15)

**`signing` (leaf, pure):** the `SignRequest` / `SignResponse` vocabulary,
the discriminated context union (`endpoint-auth` / `agent-forwarding` /
`agent-proxy`), WebAuthn-assertion → SSH PROTOCOL.u2f signature encoding, and
COSE → OpenSSH `webauthn-sk-*` public-key derivation. No imports from other
ShellWatch packages — this breaks the Node cycle (W2). The webauthn-sk-\*
signature _construction_ lives here permanently: upstream x/crypto proposals
(golang/go#69999, #71095) remain stalled and we own this format.

**`approval`:** the `PendingActionStore` (60 s TTL, resolve/deny/expire/
cancel, per-connection cancellation for #91), the dispatcher
(`Promise.allSettled` becomes a `sync.WaitGroup` over channels), and the
`Channel` interface:

```go
type Channel interface {
    Notify(ctx context.Context, a *Action, deepLink string)
    Resolved(ctx context.Context, a *Action) // clear toasts etc.
}
```

Implementations: `wschannel` (via `ws.Hub.SendToAccount`) and `pushchannel`
(webpush-go, 404/410 pruning). Slack/Telegram are future `Channel`
implementations — documented as _not yet existing_ (W15).

**The broker replaces the god-function (W1):** `sshx` signers depend on one
consumer-side interface —

```go
type SignBroker interface {
    RequestSign(ctx context.Context, req signing.SignRequest) (signing.SignResponse, error)
    RequestKeyApproval(ctx context.Context, req signing.KeyApprovalRequest) error
}
```

— implemented by `approval.Bridge` (create action → dispatch → block on
resolution channel or ctx/TTL expiry). The four Node closures become call
sites that construct the right `signing.Context`. Deny/expire returns a
sentinel error the signer maps to skip-identity (empty signature / agent
failure reply), preserving today's try-next-key behavior.

Resolution flow (unchanged semantics): `/sign/:id` page → REST
`POST /api/actions/:id/resolve` with the assertion → store resolves →
blocked `RequestSign` returns → signer builds the wire signature → SSH auth
proceeds. UV enforcement stays defense-in-depth at resolve time.

### 5.9 Auth (`internal/auth`, `internal/hydra`)

Faithful port, cleaned names:

- **Bearer gate** as chi middleware: same exempt list, same
  path→scope routing (`/api/*`+`/ws`→`ui`, `/mcp`→`mcp`,
  `/agent-proxy`→`agent`), same WS subprotocol extraction, same fail-closed
  introspection with positive-only 60 s cache (an `ephemeral.Store`
  instance), same `token_use=access_token` check, audience deliberately
  unchecked. Principal in context: `auth.Principal{AccountID, Scopes}` (W12).
- **Step-up gate** as per-route middleware on the five sensitive routes;
  tokens in an `ephemeral.Store`, action- and account-bound, single-use.
- **Hydra providers**: login/consent/logout pages (server-rendered HTML,
  ported templates), options/verify JSON endpoints, mediated DCR with the
  same local policy (redirect-URI allowlist, scope ⊆ {mcp, agent}, `ui`
  never grantable, `offline_access` always added), RFC 9728 + blended
  RFC 8414 discovery docs. Admin client: thin `net/http` wrapper.

### 5.10 MCP (`internal/mcp`) and agent proxy (`internal/agentproxy`)

**MCP:** official go-sdk, streamable HTTP mounted at `/mcp` behind bearer
gate + IP allowlist. One `AgentSession` + one notifier per `ServerSession`;
cross-account session-ID probing returns the same indistinguishable 404 as
today. The seven tools port 1:1 against `mcp-tools.md`; tool responses are
goldened. Client name/version flow into `endpoint-auth` triggers as
call-path values, not a mutable box (W11). Account-deleted teardown
subscribes to the same lifecycle event the HTTP layer uses.

**Agent proxy:** `/agent-proxy` upgrades to WS (bearer, `agent` scope),
frames binary messages into an `io.ReadWriter`, and runs
`agent.ServeAgent(compositeAgent, rw)`. The composite agent lists file keys +
account passkeys and routes _every_ sign — file key or passkey — through the
`SignBroker` (human-in-the-loop is the point of this surface). The
`X-ShellWatch-{Hostname,OS,Version}` headers are sanitized and carried as
self-reported metadata in the `agent-proxy` context, exactly as today. The
OpenSSH 10.3 `webauthn-sk-*` → `sk-*` canonicalization handling moves from
the ssh2 fork into our `agent.ExtendedAgent` implementation (application-
field check selecting the U2F wire format) — documented in `signing`.

### 5.11 SSH transport (`internal/sshx`)

- `Transport` implements the terminal `Transport` interface over
  `x/crypto/ssh`: PTY `xterm-256color` 80×24, window-change on resize,
  stdout+stderr → data, 10 s dial timeout, 90 s overall auth timeout when a
  passkey touch may be required (same constants as Node).
- **Signers, not agents:** Node's agent-class hierarchy
  (`ForwardingAgent → CompositeSshAgent → WebAuthnSshAgent`) flattens into
  `ssh.Signer` implementations — `fileSigner` (admin-only file keys),
  `webauthnSigner` (blocks on `SignBroker`, returns `ssh.Signature` with the
  webauthn extra in `Rest`), tried in order via `ssh.PublicKeysCallback`.
  Certificate support (#209) composes as `ssh.NewCertSigner(cert, signer)` —
  validated in the spike (§8).
- Agent forwarding: `auth-agent@openssh.com` channels served by the same
  `agent.ExtendedAgent` used by the proxy, with `agent-forwarding` contexts.
- Key discovery: fsnotify-based directory watcher (500 ms debounce), PEM
  scan, fingerprint upsert into `store.SSHKeys` — a port, not a redesign.
- Connection identity: per-connection UUID; teardown cancels stranded
  pending actions via `approval.CancelForConnection` (preserves #91 fix).

### 5.12 Audit (`internal/audit`)

Guaranteed subscribers (§5.2) on terminal status transitions and pending-
action lifecycle events; INSERT on open/created, UPDATE on close/resolution
with the same denormalized snapshot columns (audit never joins live tables).
Keyset pagination queries port to sqlc with the existing composite indexes.
Reserved `client_*` columns and the `ssh` source enum stay reserved (#12).

---

## 6. Concurrency model (summary)

| Concern        | Mechanism                                                                 |
| -------------- | ------------------------------------------------------------------------- |
| Session I/O    | One pump goroutine per session; buffer guarded by its own mutex           |
| Fan-out        | Guaranteed sync hooks (audit) + coalesced cap-1 wake channels (WS/MCP)    |
| Sign requests  | Request goroutine blocks on a resolution channel with ctx + TTL           |
| WS connections | Reader goroutine + writer goroutine with bounded queue per socket         |
| Sweeps/flushes | Janitor goroutines on injected `clock.Clock`, cancelled by root ctx       |
| DB             | Synchronous calls; single-writer connection; write-behind last-used flush |
| Shutdown       | Root ctx cancel → reverse-order `io.Closer` list (audit writers last)     |

No global event bus: three explicit domains of events (terminal, approval,
account lifecycle), each a typed, consumer-registered subscription — same
shape as Node's three EventEmitters, minus the accidental lossiness and
double registries.

---

## 7. Parity policy — the A–J (+K) decisions

Rule inherited from [`docs/api/README.md`](./api/README.md): the port
**preserves** every documented inconsistency; convergence is a _separate,
deliberate_ phase after cutover, changing spec + code + goldens together.

| Item                                                  | Port decision                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A/B — mixed mutation envelopes                        | Preserve exactly (generated types force this anyway). Post-cutover: converge on `{status, ...resource}`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| C — REST vs MCP endpoint-id ownership                 | Preserve both behaviors                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| D — `terminal:close` vs `terminal:closed` redundancy  | Preserve; revisit with the frontend after cutover                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| E — three end-of-buffer vocabularies                  | Preserve (`reset` on WS, `hasMore` on MCP, bare tail on REST)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| F — three error envelopes                             | Preserve on the wire; unified internally behind `apierr` (§5.5) so convergence is cheap later                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| G — 400 vs 409 state conflicts                        | Preserve per-route statuses (they're in the goldens)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| H — `source` typed as bare string                     | The generated Go type follows the spec; tightening to the enum is a spec change first                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| I — duplicate discovery docs                          | Preserve both                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| J — lone `PATCH`                                      | Preserve                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **K (new) — output offsets become byte-based (§5.3)** | **Deliberate divergence, ruled now:** offsets are opaque monotonic cursors — every client (xterm feed, MCP `read_output`, WS `reset` replay) round-trips the server's value and none does arithmetic on it. ASCII-only goldens are bit-identical (byte length == char length); multi-byte streams differ only in cursor magnitude. Document in `websocket-protocol.md`/`mcp-tools.md` ("offsets are opaque; only round-trip them") in the same change. If golden replay surfaces a fixture that _does_ embed a multi-byte-sensitive offset, regenerate that fixture from the Go server and note it in the contract. |

WS **chunk boundaries** are treated as non-contractual (goldens compare
concatenated streams); the coalesced fan-out may legally batch output frames
differently than Node. Verify this normalization assumption against the
golden harness in Phase 1 before relying on it.

---

## 8. Testing strategy

- **Unit:** stdlib `testing` + testify, table-driven; fake `clock.Clock`
  everywhere a janitor or TTL exists (no sleeps).
- **Integration (per suite, in-process):** gliderlabs/ssh echo-shell server
  (ed25519 auth, PTY, server-push, disconnect injection) + the real app on
  `httptest`/random port + official MCP Go client + coder/websocket client
  with a `waitForMessage`-style helper. Same shape as the Node harness.
- **Golden parity:** a replay harness reads the same
  `src/test/integration/__goldens__/*.json`, applies the same normalization
  rules, and diffs — REST, discovery, MCP tools, WS frames, audit
  pagination, WebAuthn envelopes. This is the acceptance gate per surface.
- **Fake authenticator:** port of the #162/#228 WebAuthn fake (P-256
  attestation/assertion generation) — straightforward in Go crypto — so
  ceremony goldens replay end-to-end.
- **Hydra:** the Node suite fakes Hydra in-memory
  (`src/test/helpers/fake-hydra.ts` — challenge lifecycle, introspection,
  client CRUD); the Go harness ports that fake as an `httptest` server. Real
  Hydra stays a dev/deploy concern, not a test dependency.

---

## 9. Migration plan

Gate each phase on its golden subset; the Node server remains the production
backend until Phase 6.

- **Phase 0 — de-risk spike** (unchanged from #210): custom `ssh.Signer`
  doing a passkey login against real OpenSSH; `ssh.NewCertSigner(cert,
webauthnSigner)` against sshd with `TrustedUserCAKeys` (the
  `webauthn-sk-ecdsa-…-cert-v01` composition); MCP go-sdk serving one tool
  to the unchanged SvelteKit client.
- **Phase 1 — skeleton:** module at repo root, config, store + goose,
  oapi-codegen pipeline + CI drift check, health/version, embedded static
  serving, golden replay harness proven against the _Node_ server first
  (validates the harness itself and the §7 chunking assumption).
- **Phase 2 — auth plane:** Hydra providers + DCR + discovery, bearer gate,
  WebAuthn ceremonies + fake authenticator, step-up, invite.
  _Goldens: discovery, DCR, WebAuthn envelopes._
- **Phase 3 — terminal core:** Manager/Session/OutputBuffer, sshx transport
  with file keys, REST sessions/endpoints/keys, WS hub.
  _Goldens: REST, WS._
- **Phase 4 — signing + agents:** signing/approval domains, webauthn signer,
  MCP surface, agent proxy, push channel.
  _Goldens: MCP tools, ceremony + action flows._
- **Phase 5 — periphery:** audit writers/readers + pagination, seeding,
  inactive-account cleanup, demo endpoints, full integration suite green.
  _Goldens: audit pagination; full suite._
- **Phase 6 — cutover:** side-by-side soak (same config, copied DB), flip
  deployment, freeze `src/` (keep for reference one release), then remove
  Node server + ssh2 fork; `docs/architecture.md` rewritten for Go.

Post-cutover (separate track): contract convergence (A–J), then #209
certificate UX and #12 SSH-server source on the now-native `x/crypto/ssh`
foundation.

---

## 10. Risks and open questions

| Risk                                                                                  | Mitigation                                                                                                                                                                            |
| ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `webauthn-sk-*` verification never lands upstream (golang/go#69999 / #71095 stalled)  | Not needed for the client path; we own the signature _construction_ in `internal/signing` permanently. Only bites if ShellWatch becomes an SSH _server_ accepting these keys directly |
| MCP go-sdk behavioral drift (Content-Type strictness, notification pacing) vs goldens | Validate in Phase 0/1; SDK is stable-API with escape hatches                                                                                                                          |
| Golden normalization may be tighter than assumed (WS chunking, offsets)               | Phase 1 runs the Go harness against the Node server first — mismatch means fixing the harness/fixtures _before_ any Go handler exists                                                 |
| gliderlabs/ssh dormancy                                                               | Test-only; vendor from Tailscale/Charm derivatives if a CVE appears                                                                                                                   |
| go-webauthn v0.x API churn                                                            | Pin; wrap in `internal/webauthn` so churn is contained                                                                                                                                |
| Feature freeze during rewrite                                                         | Phased plan keeps Node shippable through Phase 5; scope is frozen by the contract, so "done" is objective                                                                             |

[#210]: https://github.com/rado0x54/ShellWatch/issues/210
