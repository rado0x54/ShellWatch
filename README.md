# ShellWatch

SSH session broker with a browser terminal UI and MCP interface.

ShellWatch lets you manage remote terminal sessions from two interfaces:

- **Web UI** — connect to SSH endpoints and interact via an in-browser terminal (xterm.js)
- **MCP** — AI agents (e.g., Claude) can programmatically create sessions, run commands, and read output

Both interfaces share the same TerminalManager and are kept in sync in real time. Sessions created via MCP appear instantly in the UI (and vice versa).

For detailed architecture docs see [docs/architecture.md](./docs/architecture.md) and the [architecture diagram](./docs/architecture-diagram.md).

## Prerequisites

- Node.js 20+
- pnpm

## Setup

```bash
git clone https://github.com/rado0x54/ShellWatch.git
cd ShellWatch
pnpm install
```

### Configuration

```bash
cp config.sample.yaml config.yaml
```

Edit `config.yaml` with your SSH targets:

```yaml
keyDirectory: ./keys

servers:
  - id: dev-box
    label: Dev Box
    host: dev.example.com
    port: 22
    username: ubuntu
    keyId: dev-box     # matches ./keys/dev-box.pem

security:
  allowedNetworks:
    - 127.0.0.1/32
    - "::1/128"
```

Endpoints and keys can also be managed dynamically via the web UI or REST API — changes are persisted in SQLite.

### SSH key setup

Place key files in the `keys/` directory. They are auto-discovered on startup and watched for changes.

```bash
ssh-keygen -t ed25519 -f ./keys/dev-box.pem -C "shellwatch"
ssh-copy-id -i ./keys/dev-box.pem.pub ubuntu@dev.example.com
```

- Keys are matched to endpoints by `keyId` (filename without `.pem` extension)
- Key files must be readable by the current user (`chmod 600`)
- The `keys/` directory is gitignored

## Running

### Development

```bash
pnpm dev
```

Builds the SvelteKit client and starts the server on `http://localhost:3000`.

### Production

```bash
pnpm build   # compile server (tsc) + build client (SvelteKit)
pnpm start   # run production server
```

The production server auto-detects the built client in `dist/client/` and serves it as static files. No Vite dependency at runtime.

### All endpoints on a single port

| Path | Interface |
|------|-----------|
| `/` | Web UI — Terminal view |
| `/observer` | Web UI — Multi-session grid |
| `/settings/*` | Web UI — Settings (endpoints, keys, passkeys, API keys) |
| `/login` | Web UI — WebAuthn login |
| `/api/*` | REST API |
| `/ws` | WebSocket (terminal I/O + events) |
| `/mcp` | MCP (streamable HTTP) |
| `/health` | Health check |

## Web UI

Open `http://localhost:3000` in your browser.

- **Sidebar** shows configured endpoints, SSH keys, and active sessions
- Click **Connect** on an endpoint to open a terminal session
- Click a session in the sidebar to switch between terminals
- Sessions show their source — `(ui)` or `(mcp)`
- Terminal auto-resizes with the browser window
- Sessions created via MCP appear automatically — no refresh needed
- **Observer mode** — grid view to monitor multiple sessions at once

## MCP

ShellWatch exposes an MCP server over streamable HTTP at `/mcp`:

| Tool | Description |
|------|-------------|
| `shellwatch_list_endpoints` | List configured SSH endpoints |
| `shellwatch_create_session` | Create a new terminal session |
| `shellwatch_list_sessions` | List this agent's active sessions |
| `shellwatch_send_keys` | Send keystrokes/text to a session |
| `shellwatch_read_output` | Read session output (with offset) |
| `shellwatch_close_session` | Close a session |

Each MCP client gets an isolated `AgentSession` — agents can only see and control their own sessions. The web UI (admin view) sees all sessions regardless of source.

**Notifications (server -> client):**
- `output_available` — new output ready (debounced)
- `session_status` — session state changed

### Claude Desktop / Claude Code configuration

```json
{
  "mcpServers": {
    "shellwatch": {
      "type": "streamable-http",
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

## Scripts

| Script | Description |
|--------|-------------|
| `pnpm dev` | Build client + start server with hot reload |
| `pnpm build` | Build server (tsc) + client (SvelteKit) for production |
| `pnpm start` | Run production server |
| `pnpm build:server` | Compile server TypeScript only |
| `pnpm build:client` | Build SvelteKit client |
| `pnpm typecheck` | Type check without emitting |
| `pnpm lint` | Lint with ESLint |
| `pnpm lint:fix` | Auto-fix lint issues |
| `pnpm format` | Format with Prettier |
| `pnpm test` | Run all tests |
| `pnpm test:coverage` | Run tests with coverage report |

## Testing

Tests cover unit and integration scenarios. No external services needed — everything runs in-process with an embedded ssh2 server.

```bash
pnpm test           # run all tests
pnpm test:coverage  # run with coverage report
```

## Tech stack

- **Backend:** Fastify, ssh2, @modelcontextprotocol/sdk
- **Frontend:** SvelteKit (Svelte 5, adapter-static), xterm.js
- **Database:** SQLite via Drizzle ORM
- **Auth:** WebAuthn/passkeys (via @simplewebauthn)
- **Testing:** Vitest, ssh2 Server (in-process)
- **Config:** YAML + zod validation
- **Linting:** ESLint (typescript-eslint + eslint-plugin-svelte)
- **Formatting:** Prettier

## Troubleshooting

**"Private key not readable"** — Check file permissions: `chmod 600 ./keys/your-key.pem`

**"Connection timed out"** — Verify the host is reachable and the port is correct. Connection timeout is 10 seconds.

**"Auth failure"** — Ensure the private key matches the server's authorized keys and the username is correct.

**Port already in use** — Kill the existing process: `lsof -ti:3000 | xargs kill`