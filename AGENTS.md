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
- **Backend:** Fastify with plugins (`@fastify/websocket`, `@fastify/static`, `@fastify/cors`)
- **Frontend:** Vanilla TypeScript + Vite (no framework — xterm.js is the main widget)
- **SSH:** ssh2 library
- **Terminal:** xterm.js
- **Config:** YAML with zod validation
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
  index.ts            # Entry point — starts Fastify, loads config
  config/             # Config schema (zod) and YAML loader
  server/             # Fastify app, HTTP routes, WebSocket handler
  terminal/           # TerminalManager, OutputBuffer, transport interface
  mcp/                # MCP server and streamable HTTP transport
  transport/          # SSH transport implementation (ssh2)
client/               # Vite frontend app
  src/
    main.ts           # Client entry point
    style.css         # Global styles
  index.html          # HTML entry
  vite.config.ts      # Vite config with proxy to backend
config.sample.yaml    # Sample SSH endpoint config
```

## Commands

```bash
pnpm dev              # Start backend (Fastify) with hot reload
pnpm dev:client       # Start frontend (Vite) dev server
pnpm build            # Compile TypeScript
pnpm typecheck        # Type check without emitting
pnpm lint             # Check linting with Biome
pnpm lint:fix         # Auto-fix linting issues
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

MCP is served over streamable HTTP at `/mcp` (stateless, no auth). Everything runs in a single process via `pnpm dev`.

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
- **Extensible:** Structure code so observer mode, audit logs, and policy enforcement can be added later
- **Simple:** Prefer straightforward code over abstractions. This is a POC.
