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
- **Frontend:** Vanilla TypeScript + Vite (middleware mode, no framework — xterm.js is the main widget)
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
client/                 # Vite frontend app
  src/
    main.ts             # Client entry point
    api.ts              # REST API client
    ws-client.ts        # WebSocket client
    terminal-view.ts    # xterm.js terminal management
    style.css           # Global styles
  index.html            # HTML entry
config.sample.yaml      # Sample SSH endpoint config
```

## Commands

```bash
pnpm dev              # Start server (UI + API + WebSocket + MCP) with hot reload
pnpm build            # Compile TypeScript
pnpm typecheck        # Type check without emitting
pnpm lint             # Check linting with Biome
pnpm lint:fix         # Auto-fix linting issues
pnpm test             # Run all tests (unit + integration)
pnpm test:watch       # Run tests in watch mode
pnpm test:coverage    # Run tests with coverage report
```

## Architecture

```
[config.yaml]
      |
      v
[TerminalManager] ←── [MCP tools @ /mcp (streamable HTTP)]
   |          \
   |           \
   v            v
[SSH/ssh2]    [WebSocket @ /ws]
   |               |
   v               v
[Remote host]  [Web UI (xterm.js)]
```

The TerminalManager is the central abstraction. Both the WebSocket transport (for UI) and MCP tool handlers call into the same TerminalManager instance. This ensures terminal sessions are shared across interfaces.

MCP is served over streamable HTTP at `/mcp` (stateful per MCP client session, no auth). Everything runs in a single process via `pnpm dev`.

## Testing

### Philosophy
Tests cover both individual components and the full system. Integration tests use in-process infrastructure (ssh2 Server, Fastify app, MCP client, WebSocket client) — no external services needed.

### Unit Tests
- `src/terminal/output-buffer.test.ts` — buffer append, incremental reads, eviction
- `src/terminal/terminal-manager.test.ts` — lifecycle, events, idle cleanup (mock transport)
- `src/config/loader.test.ts` — valid/invalid configs, validation errors
- `src/mcp/server.test.ts` — all 6 MCP tools via InMemoryTransport
- `client/src/api.test.ts` — REST API client (mock fetch)
- `client/src/ws-client.test.ts` — WebSocket message handling, reconnect

### Integration Tests
Integration tests spin up real infrastructure per test suite:
- **In-process ssh2 Server** — ed25519 key auth, PTY, echo shell, server-push, disconnect simulation
- **ShellWatch Fastify app** — on random port, `skipVite: true` for test isolation
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
- **Extensible:** Structure code so observer mode, audit logs, and policy enforcement can be added later
- **Simple:** Prefer straightforward code over abstractions. This is a POC.
