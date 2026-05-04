<p align="center">
  <img src="./design/shellwatch_logo.svg" alt="ShellWatch" width="320">
</p>

<p align="center">
  <strong>Passkey-Authenticated SSH for Humans and Agents</strong>
</p>

<p align="center">
  <a href="https://shellwatch.ai">Website</a> ·
  <a href="https://app.shellwatch.ai">App</a> ·
  <a href="./docs/architecture.md">Architecture</a>
</p>

ShellWatch is a Human-in-the-Loop platform for agent-driven SSH. Passkey-first and passkey-only — no passwords anywhere — with an SSH-agent proxy that forwards signing requests end-to-end to a user's WebAuthn passkey. Every agent action surfaces in realtime notifications, persists in a tamper-evident audit log, and can be gated behind explicit human approval before it touches the remote host.

- **Passkey-only auth** — WebAuthn for UI login, agent enrollment, and SSH key approval
- **End-to-end SSH-agent proxy** — local `ssh`/`scp`/`git` reach a passkey via ShellWatch with explicit browser approval per signature (OpenSSH 10.3+; `verify-required` enforces UV server-side)
- **Human-in-the-loop for agents** — MCP agents request, humans approve; sensitive actions can require per-action consent
- **Realtime notifications** — sign requests arrive as Web Push and in-UI toasts
- **Tamper-evident audit log** — every signing request and session event persists to SQLite
- **Two interfaces, one core** — browser terminal (xterm.js) and MCP (streamable HTTP) share the same `TerminalManager`

## Quick start

```bash
git clone https://github.com/rado0x54/ShellWatch.git
cd ShellWatch
pnpm install
cp config.sample.yaml config.yaml
pnpm dev
```

Open <http://localhost:3000>. See `config.sample.yaml` for all options. Endpoints, keys, and passkeys are managed in the web UI — the config file only handles initial seeding and security settings.

Minimal `config.yaml`:

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
```

## Production

```bash
pnpm build   # tsc + SvelteKit
pnpm start   # serves the pre-built client from dist/client/
```

### Endpoints

| Path           | Interface                                 |
| -------------- | ----------------------------------------- |
| `/`            | Web UI                                    |
| `/observer`    | Multi-session grid                        |
| `/settings/*`  | Endpoints, keys, passkeys, API keys       |
| `/api/*`       | REST API                                  |
| `/ws`          | WebSocket (terminal I/O + events)         |
| `/mcp`         | MCP (streamable HTTP)                     |
| `/agent-proxy` | SSH agent proxy (WebSocket, API key auth) |
| `/health`      | Health check                              |

### Reverse proxy

When ShellWatch runs behind nginx/Caddy/an ALB/Cloudflare, set `server.trustProxy` to the CIDR(s) of the proxy you control so real client IPs reach the allowlist and audit log:

```yaml
server:
  externalUrl: https://shellwatch.example.com
  trustProxy:
    - 10.0.0.0/8
```

> **Do not set `trustProxy: true` in production.** That trusts `X-Forwarded-For` from any source, letting clients spoof their IP. Pin to the CIDR of the proxy you actually run. Make sure the proxy itself sets `X-Forwarded-For`. See [Fastify's docs](https://fastify.dev/docs/latest/Reference/Server/#trustproxy) for the full grammar.

## MCP

ShellWatch exposes an MCP server over streamable HTTP at `/mcp`.

| Tool                          | Description                                   |
| ----------------------------- | --------------------------------------------- |
| `shellwatch_create_session`   | Create a new terminal session                 |
| `shellwatch_list_sessions`    | List this agent's active sessions             |
| `shellwatch_send_keys`        | Send keystrokes/text to a session             |
| `shellwatch_read_output`      | Read session output (with offset)             |
| `shellwatch_close_session`    | Close a session                               |
| `shellwatch_manage_endpoints` | List, create, update, or delete SSH endpoints |
| `shellwatch_manage_keys`      | List available SSH keys                       |

Each MCP client gets an isolated `AgentSession` — agents only see their own sessions.

### Connecting an MCP client

Point your client (Claude Desktop, Claude Code, any MCP-aware tool) at the `/mcp` URL — the integrated OAuth flow handles credentials, no manual API key paste needed:

```
https://your-shellwatch-host/mcp
```

OAuth mints an `mcp`-scoped API key after browser approval. For headless setups you can still seed a static key via `seedAdminApiKey` in `config.yaml`, or create one under **Settings → API Keys**.

## Push notifications (PWA)

ShellWatch is an installable PWA with Web Push for sign requests, so approvers don't need the tab open. Generate VAPID keys and add them to `config.yaml`:

```bash
npx web-push generate-vapid-keys
```

```yaml
vapid:
  subject: "mailto:admin@example.com"
  publicKey: "BEl62i..."
  privateKey: "UGo..."
```

Enable push under **Settings → Notifications**. When `vapid` is unset, the feature is hidden.

## SSH agent proxy

ShellWatch can act as an SSH agent for system clients (`ssh`, `scp`, `git`), so your local commands authenticate via passkeys managed by ShellWatch — even when ShellWatch runs remotely.

```yaml
agentSocket:
  proxyEnabled: true
```

Run [`shellwatch-agent`](./agent-client/) on your workstation:

```bash
brew install rado0x54/tap/shellwatch-agent
shellwatch-agent login --server https://shellwatch.example.com
brew services start shellwatch-agent
eval "$(shellwatch-agent --print-env)"
```

Both WebAuthn passkeys and file-based SSH keys are supported, both require browser approval. Passkeys require **OpenSSH 10.3+** on the client. To make UV load-bearing on the server, set `PubkeyAuthOptions verify-required` in `sshd_config`. Full usage, OAuth/static-key flows, and troubleshooting in the [agent-client README](./agent-client/README.md).

## Architecture

```
[Web UI]  [MCP Agent]  [SSH Agent]
   |          |            |
   |     [AgentSession][AgentSession]
   |          |            |
   └──────────┼────────────┘
              |
      [TerminalManager]
              |
       [SSH Transport]
              |
       [Remote host]
```

Detail: [docs/architecture.md](./docs/architecture.md) · [diagram](./docs/architecture-diagram.md).

## Tech stack

Fastify · ssh2 · `@modelcontextprotocol/sdk` · SvelteKit (Svelte 5, adapter-static) · xterm.js · SQLite + Drizzle · WebAuthn (`@simplewebauthn`) · Vitest · ESLint · Prettier.

## Scripts

`pnpm dev` · `pnpm build` · `pnpm start` · `pnpm typecheck` · `pnpm lint` · `pnpm test` · `pnpm test:integration`. See `package.json` for the full list.

## Troubleshooting

- **"Private key not readable"** — `chmod 600 ./keys/your-key.pem`
- **"Connection timed out"** — verify host and port; the connection timeout is 10 seconds
- **"Auth failure"** — confirm the key matches the server's authorized keys and the username is correct
- **Port already in use** — `lsof -ti:3000 | xargs kill`
