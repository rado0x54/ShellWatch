# ShellWatch — Agent Instructions

This is the canonical project instructions file. All coding agents (Claude Code, Codex, Cursor, etc.) should read this file for project context and conventions.

## Project Overview

ShellWatch is an SSH session broker that provides:
- A browser-based terminal UI for interactive SSH sessions
- An MCP (Model Context Protocol) interface for programmatic session control
- A shared TerminalManager that both UI and MCP operate on

The goal is to act as a thin session broker between configured SSH targets, human users (via web UI), and AI agents (via MCP).

## Tech Stack

- **Runtime:** Node.js with TypeScript (strict mode)
- **Backend:** Fastify with plugins (`@fastify/websocket`, `@fastify/cors`)
- **Frontend:** SvelteKit (adapter-static, client-side SPA) with Svelte 5, xterm.js for terminal
- **SSH:** ssh2 library
- **Terminal:** xterm.js
- **MCP:** @modelcontextprotocol/sdk (streamable HTTP transport)
- **Config:** YAML with zod validation
- **Testing:** Vitest (unit + integration)
- **Linting/Formatting:** Biome
- **Package manager:** pnpm

## Code Conventions

- Use ES modules (`import`/`export`), not CommonJS (`require`)
- Destructure imports when possible: `import { foo } from 'bar'`
- TypeScript strict mode — no `any` unless absolutely necessary
- Use `.js` extensions in relative import paths (required for Node16 module resolution)
- Single-line commit messages with category prefix: `feat:`, `fix:`, `chore:`, `refactor:`, `docs:`

## Project Structure

```
src/
  index.ts              # Entry point — starts Fastify, loads config
  config/               # Config schema (zod) and YAML loader
  server/               # Fastify app, HTTP routes, WebSocket handler
  terminal/             # TerminalManager, OutputBuffer, transport interface
  mcp/                  # MCP server and streamable HTTP transport
  transport/            # SSH transport implementation (ssh2)
  test/
    helpers/            # Test infrastructure (SSH server, app, MCP/WS clients)
    integration/        # Integration tests by category
client/                 # SvelteKit frontend app (adapter-static)
  src/
    app.html            # HTML shell
    app.css             # Global styles (CSS variables, shared classes)
    lib/
      stores/           # Svelte stores (ws, endpoints, keys, webauthn, auth)
      components/       # Reusable components (Terminal, Sidebar)
      utils/            # Utilities (FIDO signing)
    routes/
      +layout.svelte    # Root layout (sidebar + mobile nav)
      +page.svelte      # Terminal view (default route)
      login/            # WebAuthn login page
      observer/         # Multi-session grid view
      settings/         # Settings with tab sub-routes
        endpoints/      # SSH endpoint management
        keys/           # SSH key listing
        passkeys/       # WebAuthn passkey management
        api-keys/       # MCP API key management
  svelte.config.js      # SvelteKit config
config.sample.yaml      # Sample SSH endpoint config
```

## Commands

```bash
# Development
pnpm dev              # Start server (UI + API + WebSocket + MCP) with hot reload

# Production
pnpm build            # Build server (tsc) + client (SvelteKit) for production
pnpm start            # Run production server (serves pre-built client)

# Build (individual)
pnpm build:server     # Compile server TypeScript only
pnpm build:client     # Build SvelteKit client (svelte-kit sync + vite build)

# Quality
pnpm typecheck        # Type check without emitting
pnpm lint             # Check linting with Biome
pnpm lint:fix         # Auto-fix linting issues
pnpm test             # Run all tests (unit + integration)
pnpm test:watch       # Run tests in watch mode
pnpm test:coverage    # Run tests with coverage report
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
- `src/mcp/server.test.ts` — all 6 MCP tools via InMemoryTransport

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

- **Local-first:** No external database or auth for the POC
- **Shared core:** UI and MCP must use the same TerminalManager — no parallel implementations
- **Real-time sync:** Session changes broadcast to all WebSocket clients immediately
- **Passkey-first:** No passwords. WebAuthn passkeys for human auth, API keys for agents.
- **Human-in-the-loop:** Agent actions can require human approval via second channel (Slack, webhook)
- **Simple:** Prefer straightforward code over abstractions. Ship function first, polish later.

## Roadmap

Open tickets in implementation order. High priority items focus on core function: MCP interface quality, persistence, security with passkeys, guardrails with human approval.

### High Priority (core function)

| Phase | Ticket | Description |
|-------|--------|-------------|
| 1 | #10 | Enhanced MCP interface — `shellwatch_exec`, `send_keys`, notifications |
| 2 | #14 | Persistence layer — Drizzle ORM, SQLite/PostgreSQL, dynamic config |
| 3 | #13 | Guardrails — input filtering with warn/block/terminate/approve actions |
| 4 | #15 | Security — IP allowlist, API keys for agents, passkey for admin |
| 5 | #18 | FIDO/hardware key — ssh2 fork, WebAuthn browser bridge for SSH signing |
| 6 | #20 | Passkey-first auth — unified WebAuthn for UI login, SSH signing, approvals |
| 7 | #19 | Human-in-the-loop — second channel notifications, interactive approvals |

### Lower Priority (extend later)

| Ticket | Description | Why deferred |
|--------|-------------|-------------|
| #11 | Google Stitch UI design | Function before polish |
| #12 | SSH server interface (bastion) | Needs auth foundation first |
| #16 | Audit log (full I/O recording) | Needs persistence, not critical for function |
| #17 | Multi-tenant (identities, scoped access) | Single-admin is sufficient for stage one |

### Dependency Graph
```
#10 Enhanced MCP ←── no deps, start immediately
#14 Persistence ←── no deps, foundational
  ↓
#13 Guardrails ←── needs #14
#15 Security ←── needs #14
  ↓
#18 FIDO/ssh2 fork ←── needs #15, can research in parallel
#20 Passkey-first ←── needs #18, #15
  ↓
#19 Human-in-the-loop ←── needs #13, #15, #20
```
