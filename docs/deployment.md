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
  `hydra.yml`).
- **`:4445` (admin)** — login/consent acceptance, client CRUD, introspection.
  **Never expose this to the internet.** ShellWatch reaches it over the trusted
  internal network only.

### Local dev (Hydra in compose, app via `pnpm dev`)

```bash
pnpm hydra:migrate                # create Hydra's schema (./data/hydra.sqlite)
docker compose up -d hydra        # naming the service starts ONLY Hydra
# Then run ShellWatch on the host:
pnpm dev          # or: pnpm build && pnpm start  (single binary serving the built client on :3000)
```

`hydra` is a profiled service in `docker-compose.yml` (alongside the `shellwatch`
app service) — naming it (`up -d hydra`) starts just Hydra; a bare
`docker compose up -d` starts the app only. Hydra's dev secret is defaulted
inline in the compose `environment:` block; for a shared/prod deployment,
override `HYDRA_SECRETS_SYSTEM` (e.g. via an `.env.hydra` passed with
`--env-file`) with a freshly generated value (`openssl rand -hex 16`). Hydra is backed by a file SQLite DB
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
> the Go server on `:3000`.

### Config

Add a `hydra:` section to `config.yaml` (see `config.sample.yaml`):

```yaml
hydra:
  # The SHARED public origin of app + OAuth (= server.externalUrl), not Hydra's
  # listener: it must equal Hydra's urls.self.issuer, which the bundled
  # hydra.yml sets to this value (see "One origin for app + OAuth" below).
  publicUrl: http://localhost:3000
  adminUrl: http://localhost:4445 # trusted-network only
  devProxyUpstream: http://localhost:4444 # LOCAL DEV ONLY — drop behind a real proxy
  spa:
    clientId: shellwatch-web # first-party public PKCE client (no secret)
```

ShellWatch provisions the public SPA client in Hydra automatically on boot
(idempotent). Hydra must be configured with
`oidc.dynamic_client_registration.enabled: false` (mediated DCR only) and its
login/consent URLs pointed at ShellWatch — see `hydra.yml`.

> **Reverse-proxy note:** ShellWatch's client-onboarding endpoints live under
> its own namespace — `POST /api/hydra/register` (mediated DCR) and
> `GET /api/hydra/authorize` (the CIMD front door) — so ownership is unambiguous
> when ShellWatch and Hydra share a hostname behind one proxy: everything under
> `/oauth2/*` (`/oauth2/auth`, `/oauth2/token`, `/oauth2/revoke`,
> `/oauth2/sessions/logout`) routes to Hydra, and `/api/*` (including both
> `/api/hydra/*` endpoints above) routes to ShellWatch. Hydra's own native DCR
> stays disabled.
>
> **The advertised `authorization_endpoint` is ShellWatch's, not Hydra's**, while
> CIMD is enabled (the default): a URL `client_id` has to be resolved into a
> Hydra client before Hydra sees the request, since Hydra would otherwise reject
> it as an unknown client. A non-URL `client_id` — the first-party SPA, every DCR
> client — is passed straight through to `/oauth2/auth` with the query string
> forwarded verbatim, so those flows are unchanged. `/oauth2/auth` must still
> route to Hydra: the front door redirects to it.
>
> Setting `hydra.cimd.enabled: false` is an operator kill switch, not a hand-off
> — `authorization_endpoint` reverts to Hydra's `/oauth2/auth` and URL
> `client_id`s stop working entirely, because Hydra cannot resolve a metadata
> document.
>
> **Outbound requests on the login path (CIMD):** resolving a document means
> ShellWatch fetches the `client_id` URL itself — HTTPS only, no redirects
> followed, 5 s deadline, 5 KB read cap, and a dial-time guard that refuses
> loopback, link-local, RFC 1918, ULA, CGNAT, multicast and other special-use
> destinations **after** DNS resolution, so a rebinding answer cannot reach an
> internal address. Documents are cached per RFC 9111 headers, clamped into
> `hydra.cimd.cacheMinSeconds`…`cacheMaxSeconds`; errors and invalid documents are
> never cached. Restrict which clients may onboard with
> `hydra.cimd.allowedHosts` / `blockedHosts` (exact hostnames; blocked wins). If
> outbound HTTPS is not available to the server, leave CIMD off and use DCR.
>
> `hydra.cimd.allowLoopbackDocuments` exists for development and testing only —
> the CIMD draft (§8.6) forbids it in production, and it re-opens the SSRF hole
> the dial-time guard closes. The server logs a warning when it is on.
>
> **Allowed redirect URIs** are configurable under
> `hydra.dcr.redirectUriPatterns` (default: loopback only) and are shared by DCR
> **and** CIMD — a document's `redirect_uris` are filtered through the same
> patterns, so a published metadata document can never widen your policy. Add a
> hosted client's callback (e.g. Claude.ai) explicitly — see
> `config.sample.yaml`. A registered loopback entry matches any port (RFC 8252
> §7.3); `localhost` does not, because it can resolve anywhere.
>
> **Auditing who onboarded:** every registration, document refresh and rejection
> is recorded in an append-only log, readable by admins at
> `GET /api/audit/oauth-clients` (UI: Audit → OAuth Clients). It is the one audit
> surface that is not account-scoped — onboarding happens before anyone signs in
> — so it is gated on the admin role instead of an account filter. Current client
> state stays in Hydra (`GET /admin/clients`), tagged with
> `metadata.shellwatch.origin` = `cimd` or `dcr`; clients registered before this
> landed have an empty metadata object and read as origin unknown.
>
> **One origin for app + OAuth (#243):** 2026-07-28-era MCP clients enforce
> RFC 8414 §3.3 — the authorization-server metadata's `issuer` must equal the
> origin it was fetched from — so ShellWatch and Hydra must share a public
> origin, with the proxy routing `/oauth2/*`, `/userinfo`,
> `/.well-known/jwks.json` and `/.well-known/openid-configuration` to Hydra and
> everything else (including the RFC 9728/8414 discovery docs, which are
> ShellWatch's own) to ShellWatch. Set `hydra.publicUrl` and Hydra's
> `urls.self.issuer` to that shared origin.
>
> **Locally**, `hydra.devProxyUpstream: http://localhost:4444` makes ShellWatch
> forward that same path set itself, so `pnpm dev` + `docker compose up -d hydra`
> give you the single origin with no local proxy — the bundled `hydra.yml`
> already issues on the app's origin. Remove the key in production, where the
> real proxy does the routing. Changing the issuer invalidates existing tokens:
> log out and back in once (and re-authorize MCP clients).
>
> **MCP streams through proxies (#243):** `/mcp` responses can be long-lived SSE
> streams (`subscriptions/listen`, `read_output` long-polls). The proxy must not
> buffer them (nginx: `proxy_buffering off;` — or
> `add_header X-Accel-Buffering no;` — on the `/mcp` location) and must forward
> all `Mcp-*` request headers unchanged — `2026-07-28` clients send required
> `Mcp-Method` / `Mcp-Name` / `Mcp-Protocol-Version` headers that the server
> validates.

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

| Variable                | Default                       | Description                                 |
| ----------------------- | ----------------------------- | ------------------------------------------- |
| `HOST`                  | `0.0.0.0`                     | Bind address                                |
| `SHELLWATCH_DB`         | `sqlite:./data/shellwatch.db` | Database connection string                  |
| `SHELLWATCH_CONFIG`     | `config.yaml`                 | Config file path (also `-config` / 1st arg) |
| `SHELLWATCH_LOG_LEVEL`  | `info`                        | `debug` / `info` / `warn` / `error`         |
| `SHELLWATCH_LOG_FORMAT` | `text`                        | `text` or `json`                            |
| `SHELLWATCH_LOG_FILE`   | —                             | Also append logs to this file               |

### Image

The image is a distroless (no shell) base carrying one statically linked Go
binary with the web UI embedded; `HEALTHCHECK` runs `shellwatch -healthcheck`,
which probes `/health` on the configured port. There is nothing to `exec`
into — use `docker logs` and the audit log.

### Running as non-root

The image runs as UID/GID `1000:1000` by default. If your host user uses a
different UID/GID, override with Docker's `--user` flag (or `user:` in
compose) and make sure the bind-mounted directories are owned by that UID/GID:

```bash
sudo chown -R 1001:1001 ./data ./keys
docker run --user 1001:1001 ...
```

```yaml
services:
  shellwatch:
    user: "1001:1001"
```

## Upgrading from the Node server

The Go server adopts a Node-created database **automatically and in place** —
same image name, same volumes, no flags. On first boot it recognizes the
drizzle-managed schema (which is byte-identical to the Go baseline), stamps
its own migration table instead of re-running anything, and records the
drizzle journal head so a rollback to the Node image applies nothing either.

Still, treat the first Go boot like any schema-touching upgrade:

1. **Back up `./data` before the first Go boot.** Adoption is in-place; the
   backup is your escape hatch, not part of the procedure.
2. **Rollback window:** rolling back to the last Node image is safe only
   while the Go schema still equals the frozen drizzle head — i.e. until the
   first ShellWatch release that ships a new database migration. After such a
   release has booted, the Node server no longer understands the schema;
   restore the pre-cutover backup instead.
3. **Half-migrated databases fail fast.** If boot stops with
   `existing database is missing table …` or
   `existing database has N of 11 Node migrations applied`, the Node server
   never finished its own migrations: run the last Node image once against
   the same data directory, let it migrate, then cut over.

## Standalone tarball

For deployments without Docker. Each release ships one tarball per Linux
architecture (`linux-amd64`, `linux-arm64`) containing the static `shellwatch`
binary (web UI embedded), `buildInfo.generated.json`, `config.sample.yaml`,
`LICENSE` and `THIRD_PARTY_LICENSES`. No runtime dependencies.

### Install

```bash
# Download the release tarball for your architecture
wget https://github.com/rado0x54/ShellWatch/releases/latest/download/shellwatch-VERSION-linux-amd64.tar.gz
tar xzf shellwatch-*-linux-amd64.tar.gz
cd shellwatch-*-linux-amd64

# Configure
cp config.sample.yaml config.yaml
# Edit config.yaml

# Run (reads ./config.yaml, ./buildInfo.generated.json and writes ./data/shellwatch.db)
./shellwatch
```

Building from source instead: `pnpm install && pnpm build` produces the same
binary at the repo root (`./shellwatch`).

### Systemd service

```ini
[Unit]
Description=ShellWatch SSH session broker
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/shellwatch
ExecStart=/opt/shellwatch/shellwatch
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
