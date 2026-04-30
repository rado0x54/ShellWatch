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

Edit `config.yaml`. See `config.sample.yaml` for all options. Minimal example:

```yaml
keyDirectory: ./keys

server:
  externalUrl: http://localhost:3000

security:
  rpId: localhost
  trustedWebauthnOrigins:
    - http://localhost:3000
  allowedNetworks:
    - 127.0.0.1/32
    - "::1/128"

# Optional: seed endpoints for the admin account on first run
# seedAdminEndpoints:
#   - label: Dev Box
#     address: ubuntu@dev.example.com

# Optional: seed a known API key for MCP / agent proxy
# seedAdminApiKey: sw_000000000000000000000000000000000000000000000000
```

Endpoints, keys, and passkeys are managed dynamically via the web UI or REST API — changes are persisted in SQLite. The config file is only for initial seeding and security settings.

### SSH key setup

Place key files in the `keys/` directory. They are auto-discovered on startup and watched for changes.

```bash
ssh-keygen -t ed25519 -f ./keys/dev-box.pem -C "shellwatch"
ssh-copy-id -i ./keys/dev-box.pem.pub ubuntu@dev.example.com
```

- Keys are auto-discovered by scanning the key directory — no config needed
- Keys are assigned to endpoints via the web UI after discovery
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

| Path           | Interface                                               |
| -------------- | ------------------------------------------------------- |
| `/`            | Web UI — Terminal view                                  |
| `/observer`    | Web UI — Multi-session grid                             |
| `/settings/*`  | Web UI — Settings (endpoints, keys, passkeys, API keys) |
| `/login`       | Web UI — WebAuthn login                                 |
| `/api/*`       | REST API                                                |
| `/ws`          | WebSocket (terminal I/O + events)                       |
| `/mcp`         | MCP (streamable HTTP)                                   |
| `/agent-proxy` | SSH agent proxy (WebSocket, API key auth)               |
| `/health`      | Health check                                            |

### Deploying behind a reverse proxy

When ShellWatch sits behind nginx, Caddy, an ALB, Cloudflare, etc., the TCP peer is the proxy — not the real client. Without configuration, every request looks like it came from the proxy, which breaks the sign-request "Source IP" display and the `security.allowedNetworks` allowlist.

Configure `server.trustProxy` to the CIDR(s) of the proxy you control:

```yaml
server:
  externalUrl: https://shellwatch.example.com
  trustProxy:
    - 10.0.0.0/8 # internal proxy CIDR(s) only
    - 172.16.0.0/12

security:
  # Real client IPs are now visible to the allowlist. Either narrow it to your
  # known clients, or open it up explicitly:
  allowedNetworks:
    - 0.0.0.0/0 # all IPv4
    - "::/0" # all IPv6
```

> **Do not set `trustProxy: true` in production.** That trusts `X-Forwarded-For` from any source, letting clients spoof their own IP. Always pin to the CIDR(s) of the proxy you actually run. Make sure the proxy itself sets `X-Forwarded-For` (e.g. nginx `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`).

`trustProxy` also accepts a number (hops to trust) or a single CIDR string. See [Fastify's docs](https://fastify.dev/docs/latest/Reference/Server/#trustproxy) for the full grammar.

## Web UI

Open `http://localhost:3000` in your browser.

- **Sidebar** shows configured endpoints, SSH keys, and active sessions
- Click **Connect** on an endpoint to open a terminal session
- Click a session in the sidebar to switch between terminals
- Sessions show their source — `(ui)` or `(mcp)`
- Terminal auto-resizes with the browser window
- Sessions created via MCP appear automatically — no refresh needed
- **Observer mode** — grid view to monitor multiple sessions at once
- **Sign-request approval** — when a sign is needed (passkey ceremony, SSH key approval), a toast and (optionally) a push notification link to a `/sign/:id` page where you approve or deny

## MCP

ShellWatch exposes an MCP server over streamable HTTP at `/mcp`:

| Tool                          | Description                                   |
| ----------------------------- | --------------------------------------------- |
| `shellwatch_create_session`   | Create a new terminal session                 |
| `shellwatch_list_sessions`    | List this agent's active sessions             |
| `shellwatch_send_keys`        | Send keystrokes/text to a session             |
| `shellwatch_read_output`      | Read session output (with offset)             |
| `shellwatch_close_session`    | Close a session                               |
| `shellwatch_manage_endpoints` | List, create, update, or delete SSH endpoints |
| `shellwatch_manage_keys`      | List available SSH keys                       |

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
      "url": "http://localhost:3000/mcp",
      "headers": {
        "Authorization": "Bearer sw_your_api_key_here"
      }
    }
  }
}
```

The API key must have `mcp` scope. Use `seedAdminApiKey` in config to seed a known key, or create one via the web UI under Settings → API Keys.

## Push Notifications (PWA)

ShellWatch is a Progressive Web App — it can be installed on mobile and desktop and supports Web Push notifications for sign requests (passkey signing, SSH key approval). This means users don't need the browser tab open to approve signing requests.

### Setup

Generate VAPID keys and add them to `config.yaml`:

```bash
npx web-push generate-vapid-keys
```

```yaml
vapid:
  subject: "mailto:admin@example.com"
  publicKey: "BEl62i..."
  privateKey: "UGo..."
```

Then enable push notifications in the web UI under Settings → Notifications. The browser will prompt for notification permission.

When a sign request arrives (from an MCP agent, SSH agent proxy, or another UI session), a native push notification appears. Tapping it opens the sign request directly.

Push notifications are optional — when `vapid` is not configured, the feature is simply hidden.

## SSH Agent Proxy

ShellWatch can act as an SSH agent for system SSH clients (`ssh`, `scp`, `git`). This allows your local `ssh` command to authenticate using keys managed by ShellWatch — including WebAuthn passkeys — even when ShellWatch runs on a remote server.

Enable in `config.yaml`:

```yaml
agentSocket:
  proxyEnabled: true
```

Then run the [`shellwatch-agent`](./agent-client/) thin client on your workstation:

```bash
# Install (Homebrew tap; blocked anonymously while this repo is private — #147):
brew install rado0x54/tap/shellwatch-agent

# Or build from source:
cd agent-client && make build       # or: go build -o shellwatch-agent ./cmd/shellwatch-agent/

# One-time browser-based login. Token persists in your OS keyring.
shellwatch-agent login --server https://shellwatch.example.com

# Run as a service via Homebrew, or use the manual launchd / systemd setup
# in agent-client/README.md for self-hosted servers.
brew services start shellwatch-agent

# In your shell profile, export the socket path:
eval "$(shellwatch-agent --print-env)"
```

`make build` injects the agent version via `-ldflags` (pulled from `git describe`) so it's surfaced to the approver on `/sign/:id`. Override with `make build VERSION=x.y.z`.

`login` uses the OAuth shim at `/oauth/authorize` to mint an `agent`-scoped API key without you ever pasting one — see [agent-client/README.md](./agent-client/README.md) for the full flow, the static-key fallback for CI/headless setups, and the credential-store layout.

Both WebAuthn passkeys and file-based SSH keys are supported for agent-proxy signing — both require browser approval (no silent auto-sign for the agent-proxy path). Passkeys require **OpenSSH 10.3+** on the client. Approval happens on the `/sign/:id` page, which also shows the agent client's self-reported hostname/OS/version when available. See the [agent-client README](./agent-client/README.md) for full usage, configuration, and troubleshooting.

### Enforcing user verification on the OpenSSH server

By default, ShellWatch performs the WebAuthn signing ceremony with `userVerification: "required"`, so every signature sent over the agent proxy carries the UV flag. (The setting is configurable per endpoint in Settings → Endpoints if you need to relax it for a specific host.) To make the UV guarantee load-bearing on the server side, configure the remote `sshd` to reject signatures whose UV flag is not set.

OpenSSH enforces UV on `sk-ecdsa-sha2-nistp256@openssh.com` and `sk-ssh-ed25519@openssh.com` keys via `verify-required` (UV flag bit `0x04`), settable globally in `sshd_config` or per-key in `authorized_keys`.

Per-key in `authorized_keys` (see `sshd(8)` AUTHORIZED_KEYS FILE FORMAT):

```
verify-required sk-ecdsa-sha2-nistp256@openssh.com AAAA... user@host
```

Global equivalent in `sshd_config`:

```
PubkeyAuthOptions verify-required
```

At authentication time, `sshd` ORs the global option with the per-key option — either source sets the requirement. With UV enforced, `sshd` parses `sk_flags` from the signature and rejects when `SSH_SK_USER_VERIFICATION_REQD` (`0x04` — the same bit as WebAuthn's UV flag) is not set, logging `user verification requirement not met`.

For a hardened deployment, prefer global `PubkeyAuthOptions verify-required` so the policy is enforced uniformly and can't be bypassed by a stale `authorized_keys` entry.

## Scripts

| Script               | Description                                            |
| -------------------- | ------------------------------------------------------ |
| `pnpm dev`           | Build client + start server with hot reload            |
| `pnpm build`         | Build server (tsc) + client (SvelteKit) for production |
| `pnpm start`         | Run production server                                  |
| `pnpm build:server`  | Compile server TypeScript only                         |
| `pnpm build:client`  | Build SvelteKit client                                 |
| `pnpm typecheck`     | Type check without emitting                            |
| `pnpm lint`          | Lint with ESLint                                       |
| `pnpm lint:fix`      | Auto-fix lint issues                                   |
| `pnpm format`        | Format with Prettier                                   |
| `pnpm test`          | Run all tests                                          |
| `pnpm test:coverage` | Run tests with coverage report                         |

## Testing

Tests cover unit and integration scenarios. No external services needed — everything runs in-process with an embedded ssh2 server.

```bash
pnpm test           # run all tests
pnpm test:coverage  # run with coverage report
```

## Tech stack

- **Backend:** Fastify (API, WebSocket, MCP, SSH — all server logic), ssh2, @modelcontextprotocol/sdk
- **Frontend:** SvelteKit (Svelte 5, adapter-static — client-side routing and build only, no SSR), xterm.js
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
