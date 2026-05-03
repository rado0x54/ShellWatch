# ShellWatch — Claude Code Instructions

This is the canonical project instructions file for Claude Code working in this repo.

## Project Overview

ShellWatch is a Human-in-the-Loop platform for agent-driven SSH. It's passkey-first and passkey-only — no passwords anywhere — with an SSH-agent proxy that forwards signing requests end-to-end to a user's WebAuthn passkey. Every agent action surfaces in realtime notifications, persists in a tamper-evident audit log, and can be gated behind explicit human approval before it touches the remote host.

Operationally, it brokers terminal sessions between configured SSH targets, human users (via the web UI), and AI agents (via MCP):

- A browser-based terminal UI for interactive SSH sessions
- An MCP (Model Context Protocol) interface for programmatic session control
- A shared TerminalManager that both UI and MCP operate on

## Tech Stack

- **Runtime:** Node.js with TypeScript (strict mode)
- **Backend:** Fastify with plugins (`@fastify/websocket`, `@fastify/cors`) — owns all server logic (API, WebSocket, MCP, SSH)
- **Frontend:** SvelteKit (adapter-static, client-side SPA) with Svelte 5, xterm.js — routing, layouts, and build only; no SSR or server-side SvelteKit features (Fastify handles that)
- **SSH:** ssh2 library
- **Terminal:** xterm.js
- **MCP:** @modelcontextprotocol/sdk (streamable HTTP transport)
- **Persistence:** Drizzle ORM with SQLite (audit log, pending actions, key/passkey storage)
- **Auth:** WebAuthn passkeys (UI), API keys (MCP/agent), OAuth provider for hosted MCP clients
- **Config:** YAML with zod validation
- **Testing:** Vitest (unit + integration)
- **Linting:** ESLint (typescript-eslint + eslint-plugin-svelte)
- **Formatting:** Prettier (prettier-plugin-svelte)
- **Package manager:** pnpm
- **Agent client:** Go binary in `agent-client/` (separate module, MIT-licensed)

## Code Conventions

- Use ES modules (`import`/`export`), not CommonJS (`require`)
- Destructure imports when possible: `import { foo } from 'bar'`
- TypeScript strict mode — no `any` unless absolutely necessary
- Use `.js` extensions in relative import paths (required for Node16 module resolution)
- Single-line commit messages with category prefix: `feat:`, `fix:`, `chore:`, `refactor:`, `docs:`
- Do not add "Generated with Claude Code" or similar AI attribution to commits or PRs
- **Functions with 5+ parameters must use a typed parameter object** instead of positional args. Export the params interface for callers.
- **Every new source file must carry an `SPDX-License-Identifier` header on its first line** (after the shebang, if any). Use `LicenseRef-FSL-1.1-Apache-2.0` for files at the repo root and `MIT` for anything under `agent-client/`. CI enforces this via `pnpm spdx:check`; run `pnpm spdx:write` to add headers to files you've just created. Comment styles by extension: `// …` for `.ts`/`.mjs`/`.js`/`.go`, `<!-- … -->` for `.svelte`/`.html`, `/* … */` for `.css`, `# …` for `.sh`/`Makefile`.

## Project Structure

```
src/
  index.ts              # Entry point — starts Fastify, loads config
  config/               # Config schema (zod) and YAML loader
  server/               # Fastify app, HTTP routes, WebSocket handler
  terminal/             # TerminalManager, OutputBuffer, transport interface
  transport/            # SSH transport implementation (ssh2)
  agent/                # AgentSession — per-agent session isolation
  agent-socket/         # Agent socket transport (Go agent-client bridge)
  mcp/                  # MCP server and streamable HTTP transport
  oauth/                # OAuth provider for hosted MCP clients
  webauthn/             # WebAuthn passkey registration and authentication
  pending-action/       # Pending-action store (human-in-the-loop approvals)
  audit/                # Audit log (signing requests, session events)
  db/                   # Drizzle ORM schema and migrations
  util/, utils/         # Shared helpers
  test/
    helpers/            # Test infrastructure (SSH server, app, MCP/WS clients)
    integration/        # Integration tests by category
client/                 # SvelteKit frontend app (adapter-static)
  src/
    app.html            # HTML shell
    app.css             # Global styles (CSS variables, shared classes)
    service-worker.ts
    lib/
      stores/           # Svelte stores (ws, endpoints, keys, webauthn, auth)
      components/       # Reusable components (Terminal, Sidebar)
      utils/            # Utilities (FIDO signing)
    routes/
      +layout.svelte    # Root layout (sidebar + mobile nav)
      +page.svelte      # Terminal view (default route)
      admin/            # Admin views
      audit/            # Audit log view
      login/            # WebAuthn login page
      observer/         # Multi-session grid view
      passkey-invite/   # Passkey invite flow
      register/         # Initial admin registration
      session/          # Session detail
      sign/             # FIDO/SSH signing approval
      settings/         # Settings with tab sub-routes
        endpoints/      # SSH endpoint management
        keys/           # SSH key listing
        passkeys/       # WebAuthn passkey management
        api-keys/       # MCP API key management
        notifications/  # Notification channel config
        general/        # General settings
agent-client/           # Go agent binary (separate module, MIT)
drizzle/                # Drizzle migrations
docs/                   # Architecture and design notes
config.sample.yaml      # Sample SSH endpoint config
```

## Commands

```bash
# Development
pnpm dev              # Start server + client (UI + API + WebSocket + MCP) with hot reload
pnpm dev:server       # Server-only hot reload

# Production
pnpm build            # Build server (tsc) + client (SvelteKit) for production
pnpm start            # Run production server (serves pre-built client)

# Build (individual)
pnpm build:server     # Compile server TypeScript only
pnpm build:client     # Build SvelteKit client (svelte-kit sync + vite build)

# Quality
pnpm typecheck        # Type check without emitting
pnpm lint             # Lint with ESLint (server + client + Svelte)
pnpm lint:fix         # Auto-fix lint issues
pnpm format           # Format with Prettier
pnpm format:check     # Check formatting without writing
pnpm test             # Run unit tests (excludes integration)
pnpm test:integration # Run integration tests
pnpm test:watch       # Run tests in watch mode
pnpm test:coverage    # Run tests with coverage report

# SPDX headers
pnpm spdx:check       # Verify all source files have SPDX headers (CI gate)
pnpm spdx:write       # Add missing SPDX headers
```

## Architecture

For detailed architecture documentation including data flows, component responsibilities, and planned extensions, see [docs/architecture.md](./docs/architecture.md).

**Key concepts:**

- **TerminalManager** — central session registry, source-agnostic. All paths converge here.
- **AgentSession** (`src/agent/`) — session isolation per agent connection. Each agent (MCP or future SSH) only sees its own sessions.
- **Web UI** — admin view, sees all sessions regardless of source via REST API + WebSocket.
- **MCP** — streamable HTTP at `/mcp`. Per-client stateful transport with debounced notifications.

```
[Web UI]  [MCP Agent]  [SSH Agent (planned)]
   |          |              |
   |     [AgentSession] [AgentSession]
   |          |              |
   └──────────┼──────────────┘
              |
      [TerminalManager]
              |
       [SSH Transport]
              |
       [Remote host]
```

## Testing

### Philosophy

Tests cover both individual components and the full system. Integration tests use in-process infrastructure (ssh2 Server, Fastify app, MCP client, WebSocket client) — no external services needed.

### Unit Tests

- `src/terminal/output-buffer.test.ts` — buffer append, incremental reads, eviction
- `src/terminal/terminal-manager.test.ts` — lifecycle, events, idle cleanup (mock transport)
- `src/config/loader.test.ts` — valid/invalid configs, validation errors
- `src/mcp/server.test.ts` — MCP tools via InMemoryTransport
- `src/mcp/http-transport.test.ts` — streamable HTTP transport behavior
- `src/transport/keys.test.ts` — SSH key handling

### Integration Tests

Integration tests spin up real infrastructure per test suite:

- **In-process ssh2 Server** — ed25519 key auth, PTY, echo shell, server-push, disconnect simulation
- **ShellWatch Fastify app** — on random port, `skipStaticFiles: true` for test isolation
- **MCP client** — `StreamableHTTPClientTransport` against the app
- **WebSocket client** — `ws` library with message buffering and `waitForMessage` helper

Test categories (`src/test/integration/`):

- `mcp-flow.test.ts` — MCP client full lifecycle
- `rest-api-flow.test.ts` — REST API CRUD + error codes
- `ws-flow.test.ts` — WebSocket attach, I/O, close, disconnect survivability
- `cross-actor.test.ts` — MCP↔WebSocket and HTTP↔MCP session visibility
- `ssh-server-events.test.ts` — server-initiated output/disconnect propagation
- `error-scenarios.test.ts` — error handling across all actors
- `concurrent-sessions.test.ts` — independent I/O, mixed actor sessions
- `agent-forward.test.ts` — agent-client SSH key forwarding
- `agent-proxy.test.ts` — agent-client proxy transport
- `oauth-flow.test.ts` — OAuth provider end-to-end flow
- `passkey-invite-flow.test.ts` — passkey invite minting and redemption
- `passkey-stepup-flow.test.ts` — step-up auth for sensitive actions

### Writing Tests

- **Unit tests** go next to the source file: `foo.ts` → `foo.test.ts`
- **Integration tests** go in `src/test/integration/`
- Use `createTestLog()` for diagnostics — logs dump automatically on test failure
- Always clean up sessions in `finally` blocks
- Use `waitForMessage(type, timeout)` for async WebSocket assertions

## Config

SSH endpoints are loaded from a YAML config file at startup:

```yaml
servers:
  - id: dev-box
    label: Dev Box
    host: dev.example.com
    port: 22
    username: ubuntu
    privateKeyPath: ./keys/dev-box.pem
```

Config path is resolved from: CLI arg > `SHELLWATCH_CONFIG` env var > `./config.yaml`

## Design Principles

- **Local-first:** No external database or auth dependency; SQLite via Drizzle is the only persistence
- **Single-instance only:** Several stores live in process memory (challenge store, pending-action store, passkey-invite slot). Running ShellWatch behind a load balancer or in cluster mode would silently break those flows — invite tokens minted on one worker won't resolve on another. The product is currently scoped to one process per deployment.
- **Account-scoped:** All operations are scoped to the calling account. Admin is a role, not a cross-account view; never imply cross-account session/output visibility.
- **Shared core:** UI and MCP must use the same TerminalManager — no parallel implementations
- **Real-time sync:** Session changes broadcast to all WebSocket clients immediately
- **Passkey-first:** No passwords. WebAuthn passkeys for human auth, API keys for agents.
- **Human-in-the-loop:** Agent actions can require human approval via second channel (Slack, webhook)
- **Simple:** Prefer straightforward code over abstractions. Ship function first, polish later.
