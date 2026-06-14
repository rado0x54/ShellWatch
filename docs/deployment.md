# Deployment

## Prerequisites

ShellWatch requires:

- A `config.yaml` file (copy `config.sample.yaml` and edit to match your environment)
- An SSH key directory with private keys for your endpoints
- A persistent directory for the SQLite database (also holds Hydra's SQLite DB)
- **Ory Hydra** (the OAuth2/OIDC authority — see below). This is a hard runtime
  dependency as of #217. It defaults to a file SQLite store alongside
  ShellWatch's own DB, so there's no separate database server to run.

## Ory Hydra (OAuth authority)

ShellWatch delegates all OAuth2/OIDC to [Ory Hydra](https://www.ory.sh/hydra/).
Every client — the **web UI**, **MCP clients**, and the **`shellwatch-agent`**
binary — uses the _same_ flow: mediated Dynamic Client Registration +
`authorization_code` + PKCE, where the user logs in with a passkey and consents.
The access token carries the identity (`sub` = account); the OAuth client is
never bound to an account. ShellWatch is Hydra's **passkey-gated login + consent
provider** — Hydra never sees a credential, it just redirects challenges back.

### Topology

```
                       passkey login/consent (ShellWatch :3000)
   [Web UI SPA] ──DCR + authcode/PKCE (tokens in browser)──────────────┐
   [MCP client] ──mediated DCR + authcode/PKCE──────────────────────────┤
   [agent-client] ──mediated DCR + authcode/PKCE (loopback browser)──────┤
                                                                          ▼
                                                                    [Ory Hydra]
                                                                  (:4444 public)
                                                                  (:4445 admin)
                                                                          │
   /api, /ws, /mcp, /agent-proxy ── Bearer ── introspect(:4445) ─────────┘
                                       sub = accountId, scope = ui|mcp|agent
                                  [SQLite ./data/hydra.sqlite]
```

- **`:4444` (public)** — discovery, `/oauth2/auth`, `/oauth2/token`,
  `/oauth2/revoke`. Reached by the browser SPA, MCP clients, and the
  agent-client. CORS must allow the web-UI origin (configured in
  `deploy/hydra/hydra.yml`).
- **`:4445` (admin)** — login/consent acceptance, client CRUD, introspection.
  **Never expose this to the internet.** ShellWatch reaches it over the trusted
  internal network only.

### Local dev (Hydra in compose, app via `pnpm dev`)

```bash
cp deploy/hydra/.env.sample .env.hydra      # dev-only secrets
pnpm hydra:migrate                          # create Hydra's schema (./data/hydra.sqlite)
docker compose --env-file .env.hydra up -d hydra   # naming the service starts ONLY Hydra
# Then run ShellWatch on the host:
pnpm dev          # or: pnpm build && pnpm start  (serves built client on :3000)
```

`hydra` is a profiled service in `docker-compose.yml` (alongside the `shellwatch`
app service) — naming it (`up -d hydra`) starts just Hydra; a bare
`docker compose up -d` starts the app only. Hydra is backed by a file SQLite DB
at `./data/hydra.sqlite` (the same folder as ShellWatch's own DB). **Migrations
are
not run automatically** — they can be destructive, so `pnpm hydra:migrate` is an
explicit, backed-up step: it copies `./data/hydra.sqlite` to a timestamped
`.bak-…` first, then applies the schema. Run it before the first `up`, and again
after bumping the Hydra image. The
passkey **login + consent providers** are server-rendered by ShellWatch at
`http://localhost:3000/api/hydra/*`; the web UI's OAuth flow (and its
`/auth/callback`) run in the browser. Point your browser at
`http://localhost:3000` for the full flow.

> Note: under `pnpm dev` the Vite dev server (`:3001`) is for SPA hot-reload
> only — the OAuth redirect flow + the login/consent providers are served by
> Fastify on `:3000`.

### Config

Add a `hydra:` section to `config.yaml` (see `config.sample.yaml`):

```yaml
hydra:
  publicUrl: http://localhost:4444 # must equal Hydra urls.self.issuer
  adminUrl: http://localhost:4445 # trusted-network only
  spa:
    clientId: shellwatch-web # first-party public PKCE client (no secret)
```

ShellWatch provisions the public SPA client in Hydra automatically on boot
(idempotent). Hydra must be configured with
`oidc.dynamic_client_registration.enabled: false` (mediated DCR only) and its
login/consent URLs pointed at ShellWatch — see `deploy/hydra/hydra.yml`.

> **Reverse-proxy note:** ShellWatch's mediated DCR endpoint is `POST
/oauth2/register` — the same path Hydra uses for its (disabled) native DCR. If
> ShellWatch and Hydra share a hostname behind one proxy, route `/oauth2/register`
> to **ShellWatch**, not Hydra (Hydra's is off, so routing it there breaks client
> registration). The other `/oauth2/*` paths (`/oauth2/auth`, `/oauth2/token`,
> `/oauth2/revoke`, `/oauth2/sessions/logout`) route to Hydra.
>
> **Allowed redirect URIs** for DCR clients are configurable under
> `hydra.dcr.redirectUriPatterns` (default: loopback only). Add a hosted client's
> callback (e.g. Claude.ai) explicitly — see `config.sample.yaml`.

### Manual verification

1. **Web UI:** sign in via passkey through the redirect flow; confirm the PWA
   survives past the old fixed TTL (browser refresh-token rotation); logout
   revokes the refresh token at Hydra.
2. **MCP:** connect an MCP client (DCR → passkey consent → tools work).
3. **Agent:** run `shellwatch-agent login` (browser passkey login → `agent`
   token); confirm `/agent-proxy` works.
4. **Revocation:** revoke a subject's Hydra sessions / log out and confirm
   access dies within the introspection cache TTL (default 60s).
5. **Scope isolation:** an `mcp`/`agent` token cannot call `/api/*` (needs `ui`).
6. Confirm the admin port (`:4445`) is not reachable from outside the host.

> Headless/CI agents: there is **no non-interactive auth path** — every agent
> does an interactive browser login. A Device Authorization Grant (RFC 8628) is
> a planned follow-up.

## Docker (recommended)

### Quick start

```bash
# Create directories
mkdir -p data keys

# Copy and edit config
cp config.sample.yaml config.yaml
# Edit config.yaml — set rpId, trustedWebauthnOrigins, etc.

# Generate an SSH key
ssh-keygen -t ed25519 -f ./keys/my-server.pem -C "shellwatch"

# Start
docker compose up -d
```

ShellWatch will be available at `http://localhost:3000`.

### docker run

```bash
docker run -d \
  -v ./config.yaml:/app/config.yaml:ro \
  -v ./data:/app/data \
  -v ./keys:/app/keys:ro \
  -p 3000:3000 \
  ghcr.io/rado0x54/shellwatch:latest
```

### Image tags

| Tag          | Description                                   |
| ------------ | --------------------------------------------- |
| `latest`     | Latest stable release                         |
| `X.Y.Z`      | Specific version                              |
| `X.Y`        | Latest patch for a minor version              |
| `stable`     | Tracks the `main` branch                      |
| `develop`    | Tracks the `develop` branch (may be unstable) |
| `sha-<hash>` | Specific commit build                         |

### Volumes

| Mount point        | Purpose                                              |
| ------------------ | ---------------------------------------------------- |
| `/app/config.yaml` | Configuration file (required, read-only recommended) |
| `/app/data`        | SQLite database (must be persisted)                  |
| `/app/keys`        | SSH private keys (read-only recommended)             |

### Environment variables

| Variable            | Default                       | Description                |
| ------------------- | ----------------------------- | -------------------------- |
| `HOST`              | `0.0.0.0`                     | Bind address               |
| `SHELLWATCH_DB`     | `sqlite:./data/shellwatch.db` | Database connection string |
| `SHELLWATCH_CONFIG` | `config.yaml`                 | Config file path           |

### Running as non-root

The image ships with a `shellwatch` user pinned to UID/GID `1000:1000` and runs
as that user by default. If your host user uses a different UID/GID, override
with Docker's `--user` flag (or `user:` in compose) and make sure the bind-
mounted directories are owned by that UID/GID:

```bash
sudo chown -R 1001:1001 ./data ./keys
docker run --user 1001:1001 ...
```

```yaml
services:
  shellwatch:
    user: "1001:1001"
```

## Standalone tarball

For deployments without Docker.

### Install

```bash
# Download the release tarball
wget https://github.com/rado0x54/ShellWatch/releases/latest/download/shellwatch-VERSION.tar.gz
tar xzf shellwatch-*.tar.gz
cd shellwatch-*

# Install production dependencies
npm i -g pnpm
pnpm install --prod

# Configure
cp config.sample.yaml config.yaml
# Edit config.yaml

# Run
node dist/index.js
```

### Systemd service

```ini
[Unit]
Description=ShellWatch SSH session broker
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/shellwatch
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
User=shellwatch
Environment=HOST=0.0.0.0

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp shellwatch.service /etc/systemd/system/
sudo systemctl enable --now shellwatch
```

## Agent client

The ShellWatch agent client is a standalone Go binary that proxies SSH agent requests through ShellWatch. It is released separately from the main application.

Download platform-specific binaries from the [agent releases](https://github.com/rado0x54/ShellWatch/releases?q=agent) on GitHub.

Available platforms: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64.

### Building from source

```bash
cd agent-client
make build                    # uses `git describe` for the version tag
make build VERSION=0.1.0      # or pin a specific version
```

The version is injected at link time via `-ldflags "-X main.Version=..."` and advertised to the server on the WebSocket handshake so it shows up on the `/sign/:id` approval page.
