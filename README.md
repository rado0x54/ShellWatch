<p align="center">
  <img src="./design/shellwatch_logo.svg" alt="" width="140">
  <br>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./design/shellwatch_wordmark-dark.svg">
    <img src="./design/shellwatch_wordmark-light.svg" alt="ShellWatch" width="360">
  </picture>
</p>

<p align="center">
  <strong>Passkey-Backed SSH for Humans and Agents</strong>
</p>

<p align="center">
  <a href="https://shellwatch.ai">Website</a> ·
  <a href="https://app.shellwatch.ai">App</a> ·
  <a href="https://docs.shellwatch.ai">Docs</a>
</p>

ShellWatch is a Human-in-the-Loop platform for agent-driven SSH. Passkey-first and passkey-only — no passwords anywhere — with an SSH-agent proxy that delivers end-to-end secure SSH authentication to your local client. Every agent action surfaces in realtime notifications, persists in a tamper-evident audit log, and can be gated behind explicit human approval before it touches the remote host.

- **Passkey-only auth** — WebAuthn for UI login, agent enrollment, and SSH authentication via OpenSSH's [`webauthn-sk-ecdsa-sha2-nistp256@openssh.com`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f) signature algorithm
- **OAuth2 delegated to Ory Hydra** — the OAuth2/OIDC layer is owned entirely by [Ory Hydra](https://www.ory.sh/hydra/). Every client (web UI, MCP, agent) authenticates through it via mediated DCR + `authorization_code` + PKCE, with passkey login + consent; ShellWatch is Hydra's passkey-gated login/consent provider and the access token's subject is the human. No passwords, no API keys.
- **End-to-end SSH-agent proxy** — local `ssh`/`scp`/`git` reach a passkey via ShellWatch with explicit browser approval per signature
- **Agent forwarding into sessions** — your passkey-backed SSH agent is forwarded into ShellWatch sessions (per-endpoint toggle), so you can hop to additional hosts and enable SSH-agent-based PAM integration
- **PAM integration** — pair with [`pam-ssh-agent-webauthn`](https://github.com/rado0x54/pam-ssh-agent-webauthn) to gate `sudo` (or any PAM-aware step) behind a passkey approval surfaced through ShellWatch
- **Human-in-the-loop for agents** — MCP agents request, humans approve; sensitive actions can require per-action consent
- **Realtime notifications** — sign requests arrive as Web Push and in-UI toasts
- **Tamper-evident audit log** — every signing request and session event is recorded for later review
- **Three ways in** — web UI for humans, MCP for AI agents, and native `ssh`/`scp`/`git` from your workstation (via the `shellwatch-agent` daemon)

## Requirements

`webauthn-sk-ecdsa-sha2-nistp256@openssh.com` support requires:

- **Server (`sshd`):** OpenSSH **8.4+**, with the algorithm explicitly enabled in `/etc/ssh/sshd_config`:

  ```
  PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com
  ```

  One-liner to append it and reload `sshd`:

  ```bash
  echo 'PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com' \
    | sudo tee -a /etc/ssh/sshd_config
  sudo systemctl reload ssh   # or: sudo systemctl reload sshd
  ```

- **Client (`ssh`):** OpenSSH **10.3+** — only when using the [SSH agent proxy](#ssh-agent-proxy). The PAM-from-inside-a-session path uses our [PAM module](https://github.com/rado0x54/pam-ssh-agent-webauthn) talking to `$SSH_AUTH_SOCK` directly, and plain ShellWatch sessions opened from the UI or MCP have no client-side OpenSSH requirement.

## Quick start

```bash
git clone https://github.com/rado0x54/ShellWatch.git
cd ShellWatch
pnpm install
cp config.sample.yaml config.yaml
pnpm dev
```

`pnpm dev` runs Fastify on `:3000` (API, WebSocket, MCP, agent-proxy) and a Vite dev server on `:3001` for the SvelteKit UI with hot reload — open <http://localhost:3001> in dev. Vite proxies WS/API/MCP traffic to Fastify, so everything works on the one URL.

See `config.sample.yaml` for all options. Endpoints, keys, and passkeys are managed in the web UI; the config file only handles initial seeding and security settings.

Minimal `config.yaml` for local dev (UI at `:3001`):

```yaml
server:
  externalUrl: http://localhost:3001

security:
  rpId: localhost
  trustedWebauthnOrigins:
    - http://localhost:3001
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

Then open <http://localhost:3000> — Fastify auto-detects `dist/client/` and serves the built UI off the same port as the API, WebSocket, MCP, and agent-proxy.

### Endpoints

| Path           | Interface                                          |
| -------------- | -------------------------------------------------- |
| `/`            | Web UI                                             |
| `/observer`    | Multi-session grid                                 |
| `/settings/*`  | Endpoints, keys, passkeys, sessions, notifications |
| `/api/*`       | REST API                                           |
| `/ws`          | WebSocket (terminal I/O + events)                  |
| `/mcp`         | MCP (streamable HTTP, OAuth bearer)                |
| `/agent-proxy` | SSH agent proxy (WebSocket, OAuth bearer)          |
| `/health`      | Health check                                       |

## Reverse proxy

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

Point your client (Claude Desktop, Claude Code, any MCP-aware tool) at the `/mcp` URL — the OAuth flow (backed by Ory Hydra) handles credentials end-to-end:

```
https://your-shellwatch-host/mcp
```

The client registers via mediated Dynamic Client Registration and you approve it with a **passkey** on the consent screen; Hydra issues an `mcp`-scoped token. Programmatic SSH-agent access works the same way — `shellwatch-agent login` runs a browser passkey login and obtains an `agent`-scoped token. See [docs/deployment.md](./docs/deployment.md#ory-hydra-oauth-authority) for the Hydra setup.

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

ShellWatch can act as an SSH agent for system clients (`ssh`, `scp`, `git`), so your local commands authenticate via passkeys managed by ShellWatch.

```yaml
agentSocket:
  proxyEnabled: true
```

Run [`shellwatch-agent`](./agent-client/) on your workstation:

```bash
brew install rado0x54/tap/shellwatch-agent
# Defaults to app.shellwatch.ai; pass `--server https://your-host` to point at a self-hosted instance.
shellwatch-agent login
brew services start shellwatch-agent
eval "$(shellwatch-agent --print-env)"
```

Every signing request requires explicit browser approval. To make user-verification load-bearing on the server, set `PubkeyAuthOptions verify-required` in `sshd_config`. Full usage, the headless static-token option, and troubleshooting in the [agent-client README](./agent-client/README.md).
