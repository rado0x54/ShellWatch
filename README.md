# ShellWatch

SSH session broker with a browser terminal UI and MCP interface.

ShellWatch lets you manage remote terminal sessions from two interfaces:

- **Web UI** — connect to SSH endpoints and interact via an in-browser terminal (xterm.js)
- **MCP** — AI agents (e.g., Claude) can programmatically create sessions, run commands, and read output

Both interfaces share the same terminal manager, so sessions created by either are visible to both.

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

- `privateKeyPath` is relative to the config file location
- Key files must be readable by the current user (`chmod 600`)
- The app validates config and key accessibility on startup

## Running

```bash
# Start the backend (HTTP + WebSocket + MCP)
pnpm dev

# In a second terminal, start the frontend dev server
pnpm dev:client
```

- Backend runs at `http://localhost:3000`
- Frontend dev server runs at `http://localhost:5173` (proxies API/WS to backend)
- MCP endpoint at `http://localhost:3000/mcp`

## Web UI

Open `http://localhost:5173` in your browser.

- **Sidebar** shows configured endpoints and active sessions
- Click **Connect** on an endpoint to open a terminal session
- Click a session in the sidebar to switch between terminals
- Click **Close** to terminate a session
- Terminal auto-resizes with the browser window

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

1. **Start the app** — `pnpm dev` + `pnpm dev:client`
2. **View endpoints** — open `http://localhost:5173`, see your configured SSH targets in the sidebar
3. **Open a session** — click "Connect" on an endpoint, an interactive terminal opens
4. **Interact** — type commands in the terminal (e.g., `ls -la`, `whoami`)
5. **Create a session via MCP** — use Claude Desktop or any MCP client to call `shellwatch_create_session`
6. **Send input via MCP** — call `shellwatch_send_input` with a command, then `shellwatch_get_output` to read the result
7. **Close sessions** — close from the UI sidebar or via `shellwatch_close_session`

Sessions created via MCP appear in the web UI sidebar and vice versa.

## Scripts

| Script | Description |
|--------|-------------|
| `pnpm dev` | Start backend with hot reload |
| `pnpm dev:client` | Start Vite frontend dev server |
| `pnpm build` | Compile TypeScript |
| `pnpm typecheck` | Type check without emitting |
| `pnpm lint` | Check with Biome |
| `pnpm lint:fix` | Auto-fix lint issues |

## Architecture

```
[config.yaml]
      |
      v
[TerminalManager] ←── [MCP tools @ /mcp]
   |          \
   |           \
   v            v
[SSH/ssh2]    [WebSocket @ /ws]
   |               |
   v               v
[Remote host]  [Web UI (xterm.js)]
```

## Troubleshooting

**"Private key not readable"** — Check file permissions: `chmod 600 ./keys/your-key.pem`

**"Connection timed out"** — Verify the host is reachable and the port is correct. Connection timeout is 10 seconds.

**"Auth failure"** — Ensure the private key matches the server's authorized keys and the username is correct.

**"Config validation error"** — Check your `config.yaml` against `config.sample.yaml`. All fields (`id`, `label`, `host`, `username`, `privateKeyPath`) are required.

## Tech stack

- **Backend:** Fastify, ssh2, @modelcontextprotocol/sdk
- **Frontend:** Vanilla TypeScript, Vite, xterm.js
- **Config:** YAML + zod validation
- **Linting:** Biome
