# ShellWatch Architecture

## Overview

ShellWatch is an SSH session broker that sits between clients (humans and AI agents) and remote SSH targets. All terminal sessions flow through a shared terminal `Manager`, enabling observation, policy enforcement, and audit from a single point.

The server is a single Go binary (`cmd/shellwatch`) with the SvelteKit web UI embedded; Ory Hydra is the only external service.

```
┌─────────────────────────────────────────────────────────┐
│                     ShellWatch                          │
│                                                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│  │ Web UI   │   │ MCP      │   │ Agent    │            │
│  │ (browser)│   │ (agents) │   │ Proxy    │            │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘            │
│       │              │              │                   │
│       │         ┌────┴─────┐        │                   │
│       │         │ Agent    │        │                   │
│       │         │ Session  │        │                   │
│       │         └────┬─────┘        │                   │
│       │              │              │                   │
│       └──────────────┼──────────────┘                   │
│                      │                                  │
│              ┌───────┴────────┐                         │
│              │ terminal.      │                         │
│              │ Manager        │                         │
│              └───────┬────────┘                         │
│                      │                                  │
│              ┌───────┴────────┐                         │
│              │ sshx transport │                         │
│              │ ┌────────────┐ │                         │
│              │ │ File keys  │ │                         │
│              │ │ (approved) │ │                         │
│              │ ├────────────┤ │                         │
│              │ │ Passkeys   │ │                         │
│              │ │ (WebAuthn) │ │                         │
│              │ └────────────┘ │                         │
│              └───────┬────────┘                         │
└──────────────────────┼──────────────────────────────────┘
                       │
                ┌──────┴──────┐
                │ Remote host │
                └─────────────┘
```

Dependencies form a DAG: `cmd/shellwatch` is the only place that knows the whole graph (it wires every package and owns the shutdown order); interface packages depend on domain packages, domain packages on leaf packages, nobody depends upward. The design rationale and the per-package specifications are in [`go-backend-architecture.md`](./go-backend-architecture.md).

## Core Components

### terminal.Manager (`internal/terminal`)

The central session registry. Owns the lifecycle of all terminal sessions regardless of source.

**Responsibilities:**

- Create/close terminal sessions against configured endpoints
- Route input to the SSH transport
- Buffer output per session (append-only with offset tracking)
- Guaranteed subscriber hooks for status changes and output (audit writers, WS hub, MCP notifier)
- Idle session janitor (`sessions.idleTimeoutMinutes` / `cleanupIntervalSeconds`)

**Key design:** the Manager is source-agnostic. It doesn't know or care whether a session was created by the web UI, an MCP agent, or an SSH client. All paths converge here. Status/output fan-out uses explicit subscriptions rather than an event emitter, so a slow consumer can never drop a lifecycle event.

**Event flow:**

```
Client input → Manager.SendInput() → Transport.Write() → Remote host
Remote host → Transport events → OutputBuffer.Append() → output subscribers (WS hub, MCP notifier)
```

### OutputBuffer (`internal/terminal`)

Append-only byte buffer per session with offset tracking.

- Supports incremental reads via `afterOffset`
- Configurable max size (default 1MB) with oldest-chunk eviction
- Enables multiple consumers to read the same output independently (UI, MCP, observers)

### Transport (`internal/terminal`, implemented by `internal/sshx`)

Interface for the underlying connection to a remote host. The only implementation is the x/crypto/ssh transport in `internal/sshx`; the interface keeps the door open for other transports (local shell, container exec).

### SSH transport and signers (`internal/sshx`)

Connects to a remote host, authenticates, allocates a PTY (xterm-256color, 80x24 default) and opens an interactive shell. Window resizes are forwarded; unexpected disconnects surface as a status change.

**Authentication** builds an ordered list of `ssh.Signer`s per connection — approval-gated file keys first (admin accounts only, enabled + present on disk), then the account's passkeys — and offers **one public-key auth method per key** through x/crypto's `ClientConfig.AuthCallback`. A denied or expired approval drops that key and moves to the next one without putting a signed attempt on the wire, so a denial never costs one of sshd's `MaxAuthTries`. The connection timeout (90 s) covers dial + auth so a human has time to touch a passkey.

- `WebAuthnSigner` — asks the human for a WebAuthn assertion through the approval broker and encodes it as the `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` wire signature (`internal/signing`)
- `approvedFileKeySigner` — a PEM key from the key directory, every use behind a `key-approve` prompt
- Forwarding agent — when `agentForward` is on, the same signers are served to the remote `auth-agent@openssh.com` channel (`internal/signagent`), producing `agent-forwarding` sign requests

### Key directory (`internal/sshx/keys.go`)

Watches the key directory (fsnotify) for private key files. Auto-discovers keys on startup and on change, extracts fingerprints and public keys, and registers them in `ssh_keys` so `GET /api/keys` lists them and file-key auth can find them.

## Authentication & WebAuthn

### WebAuthn / Passkeys (`internal/webauthn`, `internal/signing`)

ShellWatch uses WebAuthn passkeys (YubiKeys, platform authenticators) for both user authentication and SSH key signing.

**Key types:**

- `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` — OpenSSH algorithm for browser-registered FIDO2 credentials (OpenSSH ≥ 10.3 on the target)
- Standard file-based keys (ed25519, RSA, ECDSA) — approval-gated, no WebAuthn ceremony

**Components:**

| Package / file                   | Purpose                                                                                         |
| -------------------------------- | ----------------------------------------------------------------------------------------------- |
| `internal/webauthn/verify.go`    | Registration + assertion verification (go-webauthn), ES256 only                                 |
| `internal/webauthn/challenge.go` | Purpose-tagged challenge store (TTL, single use)                                                |
| `internal/webauthn/stepup.go`    | Step-up tokens for sensitive actions (passkey revoke, authorized-client revoke)                 |
| `internal/webauthn/invite*.go`   | Cross-device passkey invite slot + routes                                                       |
| `internal/webauthn/cose.go`      | COSE public key → OpenSSH `authorized_keys` line                                                |
| `internal/signing`               | Leaf package: sign-request types, WebAuthn assertion → SSH signature wire format (PROTOCOL.u2f) |

Approval flow (passkey signing, file-key approval) is decoupled from the browser connection via the **pending-action** system below.

### Pending actions & sign requests (`internal/approval`)

Unified approval system for all human-in-the-loop interactions (passkey signing, file-key approval). Decouples sign requests from the browser's live WebSocket — an approver can be notified via WebSocket toast or Web Push and can approve from any browser (or phone) authenticated to the account.

| File            | Purpose                                                                                             |
| --------------- | --------------------------------------------------------------------------------------------------- |
| `store.go`      | Pending-action store — TTL map (60 s) with resolve/deny/expire/cancel; sweeps on a ticker           |
| `broker.go`     | Creates an action for a signer, fans it out to channels, blocks until a human answers or it expires |
| `ws_channel.go` | `sign:request` / `sign:resolved` to the account's connected browsers                                |
| `internal/push` | Web Push channel (VAPID) with an endpoint allowlist as SSRF guard                                   |

**Sign request sources:**

| Source             | When                                                                         | Key fields                                                                                        |
| ------------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `endpoint-auth`    | ShellWatch's own SSH client auth to an endpoint (UI- or MCP-triggered)       | `endpointLabel`, `endpointAddress`, `trigger: { kind: "ui" \| "mcp" }`                            |
| `agent-forwarding` | Downstream `auth-agent@openssh.com` channel from a running session           | `endpointLabel`, `endpointAddress`, `sessionId` of parent session                                 |
| `agent-proxy`      | Remote `shellwatch-agent` Go client requesting a sign over `/agent-proxy` WS | `sourceIp`, the requesting OAuth client's label + id prefix, optional `clientHostname/OS/Version` |

Client-reported fields on `agent-proxy` (hostname/OS/version from `X-ShellWatch-*` handshake headers) and MCP client name/version on `endpoint-auth` triggers are shown in a separate "self-reported" block on `/sign/:id` so approvers don't mistake spoofable data for authoritative identity.

**Approval flow:**

```
1. A signer's Sign() asks the broker for an approval
2. The broker stores a PendingAction (optional redirectTo) and fans it out (WS + Push)
3. Approver opens /sign/:id — GET /api/actions/:id returns the action
4. For agent-forwarding, the page also fetches /api/sessions/:id/tail to
   show the parent session's current output (pre-approval context)
5. User approves → POST /api/actions/:id/resolve (WebAuthn assertion payload for
   webauthn-sign, empty body for key-approve)
6. The broker returns the result to the waiting signer → signature goes to sshd
7. Browser navigates to redirectTo (e.g. /session/<new-session-id>)
```

Actions expire after 60 s; a denial or expiry is returned to the SSH client as "skip this key". When the terminal connection that owns a prompt dies, its pending prompts are cancelled and the toasts cleared.

### Accounts (`internal/store`)

- Admin account (single, created on first passkey registration or seeded from config)
- Non-admin accounts (via self-registration or passkey invite)
- Passkey-first authentication — no passwords
- Inactive account cleanup (90+ days, admin exempt); deleting an account closes its sessions, drops its MCP transports and revokes its Hydra sessions

### OAuth2 / OIDC — fully delegated to Ory Hydra (`internal/hydra`, `internal/auth`)

ShellWatch runs **no OAuth logic of its own** — [Ory Hydra](https://www.ory.sh/hydra/) is the single OAuth2/OIDC authority for every client (web UI, MCP, agent). ShellWatch is Hydra's **passkey-gated login + consent provider** and verifies the bearer tokens Hydra issues; it never sees a password and stores no client secrets or API keys.

- **One flow for everyone:** mediated Dynamic Client Registration (`POST /api/hydra/register`) → `authorization_code` + PKCE → passkey login + consent. The access token's `sub` is the ShellWatch account; an OAuth client is never bound to an account, and the granted `scope` (`ui` / `mcp` / `agent`) selects the surface.
- **Single bearer gate** (`internal/auth`): every authenticated surface presents an opaque Hydra access token, introspected (RFC 7662, cached for `hydra.introspectionCacheTtlMs`) and authorized by path — `ui` for `/api/*` + `/ws`, `mcp` for `/mcp`, `agent` for `/agent-proxy`. Introspection fails closed.
- **Tokens, not cookies:** the web UI is a public PKCE client holding its tokens in the browser. No server-side session, no session cookie, no API keys.
- **Components** (`internal/hydra`): login/consent/logout providers with server-rendered passkey pages, mediated DCR, RFC 9728/8414 discovery documents, the thin admin-API client, the caching bearer resolver, and first-party SPA client provisioning on boot. Hydra itself runs as a separate service backed by its own SQLite DB (`./data/hydra.sqlite`).

## Client Interfaces

### Web UI (`client/`)

SvelteKit SPA (adapter-static) built into `web/dist` and embedded into the server binary (`web/embed.go`); unknown non-API paths fall back to `index.html`. SvelteKit provides client-side routing, layouts, and the build pipeline — no SSR, no server routes. The UI uses xterm.js for terminal emulation and Svelte stores for state.

**Routes:**
| Route | View |
|-------|------|
| `/` | Terminal — single active session with xterm.js |
| `/session/[id]` | Specific session terminal view |
| `/observer` | Observer — multi-session grid (dynamic layout) |
| `/sign/[id]` | Sign-request approval page (passkey ceremony or key approval) |
| `/settings/endpoints` | SSH endpoint CRUD |
| `/settings/keys` | SSH key listing |
| `/settings/passkeys` | WebAuthn passkey management |
| `/settings/sessions` | Authorized clients (Hydra consent sessions) |
| `/settings/notifications` | Web Push subscription management |
| `/audit/sessions` | Session-lifecycle audit log |
| `/audit/signings` | Signing-request audit log |
| `/admin/accounts` | Admin: account management |
| `/admin/general` | Admin: general settings |
| `/passkey-invite/[token]` | Cross-device passkey enrollment (token-gated) |
| `/auth/callback` | OAuth redirect target — exchanges the authorization code for tokens |
| `/register` | WebAuthn passkey registration (bootstrap / self-register) |

**Communication:**

- **REST API** (`/api/*`, `internal/rest`) — endpoint/session/key/WebAuthn CRUD, action resolve/deny, session tail, audit pages. The contract is [`docs/api/openapi.yaml`](./api/openapi.yaml); response models are generated into `internal/api`.
- **WebSocket** (`/ws`, `internal/ws`) — real-time terminal I/O and session events; also carries `sign:request` / `sign:resolved` from the approval layer. Protocol: [`docs/api/websocket-protocol.md`](./api/websocket-protocol.md).

The web UI sees ALL of the account's sessions regardless of source, labelled `ui` / `mcp`. The hub broadcasts `sessions:changed` on every status change, so MCP-created sessions appear instantly.

### MCP Server (`internal/mcp`)

Stateless streamable HTTP MCP endpoint at `/mcp` (official Go SDK), serving spec revision `2026-07-28` alongside the `2025-11-25`/`2025-06-18` handshake eras (#243). There are no protocol-level sessions: every POST builds a fresh SDK server bound to an `AgentSession` (`internal/agent`) scoped to the request's `(account, OAuth client_id)`. Requires a bearer token with the `mcp` scope and a source IP inside `security.allowedNetworks`.

**Tools:** `shellwatch_create_session`, `shellwatch_list_sessions`, `shellwatch_send_keys`, `shellwatch_read_output` (with `waitMs` long-polling), `shellwatch_close_session`, `shellwatch_manage_endpoints`, `shellwatch_manage_keys` — payloads in [`docs/api/mcp-tools.md`](./api/mcp-tools.md).

**Server→client updates:** sessions are resources (`shellwatch://sessions`, `shellwatch://sessions/{id}`); `2026-07-28` clients subscribe over `subscriptions/listen` and receive `notifications/resources/updated` — debounced per session for output (`notifications.mcp.debounceMs`, default 100 ms), immediate for status changes. Older clients long-poll with `read_output waitMs`.

**Session lifecycle:** terminal sessions belong to the agent's OAuth client and survive its connections. They end via `close_session`, remote hangup, the idle janitor (`sessions.idleTimeoutMinutes`), account deletion, or consent revocation of the owning client.

### SSH Agent Proxy (`internal/agentproxy`)

WebSocket endpoint at `/agent-proxy` that bridges the SSH agent protocol for remote clients. A thin Go client ([`shellwatch-agent`](../agent-client/)) on the user's workstation relays SSH agent protocol frames over WebSocket; the server answers them with the same broker-backed signers used for sessions (`internal/signagent`). Protocol: [`docs/api/agent-proxy-protocol.md`](./api/agent-proxy-protocol.md).

```
ssh client → Unix socket → shellwatch-agent (Go) → WSS → ShellWatch /agent-proxy
                                                          │
                                                          ├─ file keys (approval-gated)
                                                          └─ passkeys (browser-signed via WebAuthn)
```

- Both passkey signs _and_ file-key uses create pending actions (no silent file-key auto-sign anywhere)
- A denied request answers `SSH_AGENT_FAILURE`, on which OpenSSH moves to its next identity
- Requires a bearer token with the `agent` scope and OpenSSH 10.3+ on the client for passkey support (#36)
- Client advertises `X-ShellWatch-Hostname` / `-OS` / `-Version` headers, sanitized server-side and rendered as "self-reported"

## Agent Layer (`internal/agent`)

`AgentSession` manages terminal sessions owned by a single agent connection and enforces isolation — an agent can only see and act on sessions it created. One `AgentSession` per MCP transport; the web UI does not use it (REST + WS operate on the Manager directly, account-scoped).

## Persistence (`internal/store`)

Single-file SQLite database (`data/shellwatch.db`, pure-Go driver, WAL mode, writes serialized through one connection). Queries are generated by sqlc (`internal/store/queries` → `internal/store/gen`); migrations are embedded and applied by goose at startup. The schema is the one the Node backend left behind: a Drizzle-managed database is adopted in place (baseline stamped, journal preserved), so a cutover needs no data migration.

| Table                     | Purpose                                                                            |
| ------------------------- | ---------------------------------------------------------------------------------- |
| `accounts`                | User accounts (admin flag, session limits, last used)                              |
| `admin_account`           | Single-row pointer table identifying the admin account                             |
| `webauthn_credentials`    | Passkey credentials (COSE public key, OpenSSH public key, label)                   |
| `ssh_keys`                | File-based SSH key metadata (fingerprint, public key — private keys on filesystem) |
| `endpoints`               | SSH target configuration (host, port, username, agent forwarding, UV policy)       |
| `audit_session_lifecycle` | Append-only session audit log (open/close events, source, timestamps)              |
| `audit_signing_requests`  | Signing-request audit log (passkey signs, key approvals — outcomes + metadata)     |
| `push_subscriptions`      | Web Push subscriptions per account (endpoint, auth/p256dh keys)                    |

OAuth clients, tokens, and consent/login sessions are **not** stored here — they live in Hydra.

## Audit Log (`internal/audit`)

Append-only audit of session lifecycle and signing-request outcomes. Writers are guaranteed subscribers of the Manager and the pending-action store; readers are keyset-paginated and never join live tables, so a passkey rename or endpoint relabel never rewrites history. All audit reads are account-scoped — admin is a role, not a global view.

## Security

- **Bearer gate** (`internal/auth/gate.go`) — the single authentication gate for `/api/*`, `/ws` (token via `Sec-WebSocket-Protocol`), `/mcp` and `/agent-proxy`; scope by path; introspection fails closed.
- **IP allowlist** (`internal/auth/ipallowlist.go`) — CIDR filter on `/mcp` and `/agent-proxy` (`security.allowedNetworks`, default loopback). Handles IPv4, IPv6 and IPv4-mapped IPv6.
- **Client IP** (`internal/realip`) — `server.trustProxy` decides whether `X-Forwarded-For` is honoured (false, true, or CIDR list; hop counts are rejected at config load).
- **Rate limits** (`internal/ratelimit`) — per-IP limits on self-registration, passkey registration and login ceremonies (`security.rateLimit`).
- **Step-up** — revoking a passkey or an authorized client requires a fresh passkey assertion.

## Configuration

```yaml
keyDirectory: ./keys # SSH key auto-discovery directory

security:
  rpId: localhost # WebAuthn Relying Party ID (required)
  trustedWebauthnOrigins: # Allowed origins for WebAuthn (required)
    - http://localhost:3000
  allowedNetworks: # CIDR allowlist for MCP/agent proxy
    - 127.0.0.1/32
    - "::1/128"

server:
  port: 3000 # HTTP port (bind address via $HOST, default 0.0.0.0)
  externalUrl: http://localhost:3000 # required — issuer/redirect base for OAuth

hydra: # OAuth2/OIDC authority (required)
  publicUrl: http://localhost:3000 # shared public origin of app + OAuth (= Hydra urls.self.issuer)
  adminUrl: http://localhost:4445 # Hydra admin API (trusted-network only)
  devProxyUpstream: http://localhost:4444 # local dev only: forward Hydra's public surface
  spa:
    clientId: shellwatch-web # first-party PKCE client (no secret)

agentSocket:
  proxyEnabled: true # Enable /agent-proxy WebSocket endpoint

sessions:
  idleTimeoutMinutes: 30 # idle janitor
  cleanupIntervalSeconds: 60

notifications:
  mcp:
    debounceMs: 100 # output_available debounce

# Seeding (first run only)
seedAdminEndpoints:
  - label: Dev Box
    address: ubuntu@dev.example.com
seedAdminPasskeys:
  - credentialId: base64url...
    publicKeyHex: hex...
```

Config is loaded from `--config` / positional arg > `SHELLWATCH_CONFIG` > `./config.yaml` and validated at startup (`internal/config`). See `config.sample.yaml` for all options.

## Process Model

Everything runs in a single Go process:

```
┌─────────────────────────────────────────┐
│          shellwatch (Go binary)         │
│                                         │
│  net/http + chi (:3000)                 │
│    ├── REST API (/api/*)                │
│    ├── WebSocket hub (/ws)              │
│    ├── MCP streamable HTTP (/mcp)       │
│    ├── Agent proxy WebSocket            │
│    │   (/agent-proxy)                   │
│    ├── Hydra login/consent providers    │
│    ├── Health / version / config.js     │
│    └── Embedded SvelteKit SPA (/)       │
│                                         │
│  terminal.Manager                       │
│    └── x/crypto/ssh connections         │
│                                         │
│  approval.Broker + Store                │
│    └── Approval queue (60s TTL)         │
│    └── WebSocket + Web Push channels    │
│                                         │
│  sshx key directory watcher             │
│                                         │
│  Janitors: idle sessions, pending       │
│    actions, MCP sessions, inactive      │
│    accounts, last-used flusher          │
│                                         │
│  SQLite (modernc, WAL, single writer)   │
└─────────────────────────────────────────┘
```

Shutdown on SIGINT/SIGTERM is ordered: stop accepting HTTP → close all terminals → final last-used flush → close the DB.

## Data Flow Examples

### Agent runs a command via MCP

```
1. MCP client calls shellwatch_send_keys(sessionId, ["text:ls -la", "enter"])
2. AgentSession.SendKeys() checks ownership → resolves key names to bytes
3. Manager.SendInput() writes to the sshx transport
4. Remote shell executes; output arrives on the transport's event channel
5. Manager appends to the OutputBuffer and notifies output subscribers
6. MCP notifier (debounced) sends output_available; WS hub forwards terminal:output
7. MCP client calls shellwatch_read_output(sessionId, afterOffset)
8. AgentSession.ReadOutput() checks ownership → reads from the OutputBuffer
```

### Session created via MCP appears in web UI

```
1. MCP client calls shellwatch_create_session(endpointId)
2. AgentSession.CreateSession() → Manager.Create()
3. Manager establishes the SSH connection (approvals as needed)
4. Manager publishes status "open" to its subscribers
5. WS hub broadcasts sessions:changed to the account's browser clients
6. Browser renders the new session with an "(mcp)" label
7. Browser user clicks it → terminal:attach → receives buffered output
```

### SSH via agent proxy with passkey signing

```
1. ssh client connects to the shellwatch-agent Unix socket
2. shellwatch-agent opens WSS to ShellWatch /agent-proxy
   (advertises X-ShellWatch-Hostname / -OS / -Version headers)
3. SSH client sends SSH_AGENTC_REQUEST_IDENTITIES → file keys + passkeys
4. SSH client sends SSH_AGENTC_SIGN_REQUEST for a passkey
5. The WebAuthnSigner asks the broker; a PendingAction with an agent-proxy
   context (OAuth client label, client metadata) is created
6. Channels fan out (sign:request via WS, Web Push); user sees a toast/notification
7. User opens /sign/:id, taps passkey → WebAuthn ceremony in browser
8. Browser POSTs the assertion to /api/actions/:id/resolve
9. The broker hands the result to the waiting signer → SSH wire signature
10. Signature returned to the SSH client via the agent proxy → sshd accepts
```

## File Structure

```
cmd/shellwatch/main.go          # Composition root: flags/env → config → wire → run → ordered shutdown
internal/
  api/                          # oapi-codegen model types from docs/api/openapi.yaml (generated; committed)
  httpserver/                   # chi router, middleware stack, route mounting, SPA fallback
  rest/                         # REST handlers (endpoints, sessions, keys, actions, audit, accounts, credentials, push)
  ws/                           # Browser WebSocket hub + protocol
  mcp/                          # MCP server, tools, per-session notifier, session janitor
  agentproxy/                   # /agent-proxy framing ↔ agent protocol
  agent/                        # AgentSession — per-agent session isolation
  terminal/                     # Manager, Session, OutputBuffer, Transport interface, key map
  sshx/                         # x/crypto/ssh transport, per-key auth, WebAuthn + file-key signers, key directory
  signagent/                    # SSH agent protocol server used by forwarding and the proxy
  signing/                      # Leaf: sign-request types, WebAuthn → SSH signature wire format
  approval/                     # Pending-action store, broker, WS channel
  push/                         # Web Push channel + endpoint allowlist
  webauthn/                     # Ceremonies (go-webauthn), challenge/step-up/invite stores, COSE → OpenSSH
  hydra/                        # Login/consent/logout providers, mediated DCR, discovery, admin client, bearer resolver
  auth/                         # Bearer gate, scope routing, IP allowlist, Principal
  realip/, ratelimit/           # Client IP under trustProxy; ceremony rate limits
  audit/                        # Lifecycle + signing writers and keyset readers
  store/                        # sqlc queries (gen/), goose migrations, repositories
  seed/, demo/, endpointsvc/    # First-run seeding, demo endpoints, endpoint service
  config/                       # YAML load, defaults, validation
  ephemeral/, clock/            # TTL store; injectable clock
  buildinfo/                    # Build identity for /api/version and /config.js
  golden/                       # Golden normalization + coverage guard (tests)
  hydratest/, webauthntest/     # Fake Hydra and fake authenticator for Go tests
web/embed.go                    # go:embed of the SvelteKit build (web/dist)
testdata/goldens/               # Golden wire fixtures (parity oracle)
client/                         # SvelteKit frontend (adapter-static → web/dist)
e2e/                            # Black-box suite: real sshd + real Hydra (docs/testing.md)
docs/api/                       # Wire contract (OpenAPI, WS, MCP, agent-proxy)
agent-client/                   # Go thin client for the SSH agent proxy (separate module, MIT)
```

## Planned Architecture Extensions

See individual tickets for details:

- **Guardrails (#13)** — input filtering layer in the Manager, before `SendInput()`
- **SSH Server (#12)** — an SSH server front door for agents, username-based routing, uses `AgentSession`
- **Certificate UX (#209)** — `ssh.NewCertSigner` composition on the x/crypto foundation
- **Host-key verification (#241)** — pin endpoint host keys instead of `InsecureIgnoreHostKey`
- **Telegram notification channel** — another `approval.Channel` alongside WS/Push
