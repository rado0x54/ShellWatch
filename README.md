# ShellWatch

SSH session broker with a browser terminal UI and MCP interface.

ShellWatch lets you manage remote terminal sessions from two interfaces:

- **Web UI** — connect to SSH endpoints and interact via an in-browser terminal (xterm.js)
- **MCP** — AI agents (e.g., Claude) can programmatically create sessions, run commands, and read output

Both interfaces share the same TerminalManager and are kept in sync in real time. Sessions created via MCP appear instantly in the UI (and vice versa). If no terminal is active in the browser, new MCP-created sessions auto-attach.

This is a **POC** — no auth, no database, no user management. SSH endpoints are loaded from a static YAML config file.

## Prerequisites

- Node.js 20+
- pnpm

## Setup

```bash
# Clone and install
git clone https://github.com/rado0x54/ShellWatch.git
cd ShellWatch
pnpm install

# Configure SSH endpoints
cp config.sample.yaml config.yaml
```

Edit `config.yaml` with your SSH targets:

```yaml
servers:
  - id: dev-box
    label: Dev Box
    host: dev.example.com
    port: 22
    username: ubuntu
    privateKeyPath: ./keys/dev-box.pem
```

### SSH key setup

Generate an ed25519 key:

```bash
ssh-keygen -t ed25519 -f ./keys/dev-box.pem -C "shellwatch"
```

Add the public key to the remote server:

```bash
ssh-copy-id -i ./keys/dev-box.pem.pub ubuntu@dev.example.com
```

- `privateKeyPath` is relative to the config file location
- Key files must be readable by the current user (`chmod 600`)
- The `keys/` directory is gitignored

## Running

```bash
pnpm dev
```

Everything runs on a single port — open `http://localhost:3000`:

- Web UI served via Vite (with HMR)
- REST API at `/api/*`
- WebSocket at `/ws`
- MCP endpoint at `/mcp`

## Web UI

Open `http://localhost:3000` in your browser.

- **Sidebar** shows configured endpoints and active sessions
- Click **Connect** on an endpoint to open a terminal session
- Click a session in the sidebar to switch between terminals
- Sessions show their source — `(ui)` or `(mcp)`
- Click **Close** to terminate a session
- Terminal auto-resizes with the browser window
- Sessions created via MCP appear automatically — no refresh needed
- If no terminal is active, new sessions auto-attach

## MCP

ShellWatch exposes an MCP server over streamable HTTP at `/mcp` with 6 tools:

| Tool | Description |
|------|-------------|
| `shellwatch_list_endpoints` | List configured SSH endpoints |
| `shellwatch_create_session` | Create a new terminal session |
| `shellwatch_list_sessions` | List active sessions |
| `shellwatch_send_input` | Send text input to a session |
| `shellwatch_get_output` | Read buffered output (supports offset/limit) |
| `shellwatch_close_session` | Close a session |

Each MCP client session gets its own stateful transport. All sessions share the same TerminalManager, so they are visible across all clients and the web UI.

### Claude Desktop configuration

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

## Demo walkthrough

1. **Start the app** — `pnpm dev`
2. **Open the UI** — navigate to `http://localhost:3000`
3. **View endpoints** — see your configured SSH targets in the sidebar
4. **Open a session from UI** — click "Connect", an interactive terminal opens
5. **Interact** — type commands in the terminal (e.g., `ls -la`, `whoami`)
6. **Create a session via MCP** — use Claude Desktop or any MCP client to call `shellwatch_create_session` — it appears in the UI instantly
7. **Send input via MCP** — call `shellwatch_send_input` with a command, then `shellwatch_get_output` to read the result
8. **Switch sessions** — click between sessions in the sidebar
9. **Close sessions** — close from the UI sidebar or via `shellwatch_close_session`

## Scripts

| Script | Description |
|--------|-------------|
| `pnpm dev` | Start server with hot reload (UI + API + WebSocket + MCP) |
| `pnpm build` | Compile TypeScript |
| `pnpm typecheck` | Type check without emitting |
| `pnpm lint` | Check with Biome |
| `pnpm lint:fix` | Auto-fix lint issues |

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

The TerminalManager is the shared core. It emits events on session state changes, which the WebSocket handler broadcasts to all connected browser clients. This keeps the UI in sync regardless of whether sessions are created from the UI or MCP.

## Troubleshooting

**"Private key not readable"** — Check file permissions: `chmod 600 ./keys/your-key.pem`

**"Connection timed out"** — Verify the host is reachable and the port is correct. Connection timeout is 10 seconds.

**"Auth failure"** — Ensure the private key matches the server's authorized keys and the username is correct.

**"Config validation error"** — Check your `config.yaml` against `config.sample.yaml`. All fields (`id`, `label`, `host`, `username`, `privateKeyPath`) are required.

**Port already in use** — Kill the existing process: `lsof -ti:3000 | xargs kill`

## Tech stack

- **Backend:** Fastify, ssh2, @modelcontextprotocol/sdk
- **Frontend:** Vanilla TypeScript, Vite (middleware mode), xterm.js
- **Config:** YAML + zod validation
- **Linting:** Biome
