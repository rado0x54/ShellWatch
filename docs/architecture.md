# ShellWatch Architecture

## Overview

ShellWatch is an SSH session broker that sits between clients (humans and AI agents) and remote SSH targets. All terminal sessions flow through a shared `TerminalManager`, enabling observation, policy enforcement, and audit from a single point.

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
│              │ Terminal       │                         │
│              │ Manager        │                         │
│              └───────┬────────┘                         │
│                      │                                  │
│              ┌───────┴────────┐                         │
│              │ SSH Transport  │                         │
│              │ Factory        │                         │
│              │ ┌────────────┐ │                         │
│              │ │ File keys  │ │                         │
│              │ │ (auto-sign)│ │                         │
│              │ ├────────────┤ │                         │
│              │ │ Passkeys   │ │                         │
│              │ │ (WebAuthn) │ │                         │
│              │ └────────────┘ │                         │
│              └───────┬────────┘                         │
│                      │                                  │
└──────────────────────┼──────────────────────────────────┘
                       │
               ┌───────┴────────┐
               │ Remote SSH     │
               │ Targets        │
               └────────────────┘
```

## Core Components

### TerminalManager (`src/terminal/terminal-manager.ts`)

The central session registry. Owns the lifecycle of all terminal sessions regardless of source.

**Responsibilities:**

- Create/close terminal sessions against configured endpoints
- Route input to the SSH transport
- Buffer output per session (append-only with offset tracking)
- Emit events: `output`, `status-change`, `close`
- Idle session cleanup (configurable timeout)

**Key design:** The TerminalManager is source-agnostic. It doesn't know or care whether a session was created by the web UI, an MCP agent, or an SSH client. All paths converge here.

**Event flow:**

```
Client input → TerminalManager.sendInput() → SSH Transport → Remote host
Remote host → SSH Transport (data event) → OutputBuffer.append() → TerminalManager emits "output"
```

### OutputBuffer (`src/terminal/output-buffer.ts`)

Append-only buffer per session with byte offset tracking.

- Supports incremental reads via `afterOffset` parameter
- Configurable max size (default 1MB) with oldest-chunk eviction
- Enables multiple consumers to read the same output independently (UI, MCP, future observers)

### TerminalTransport (`src/terminal/transport.ts`)

Interface for the underlying connection to a remote host. Currently implemented by `SshTransport` (ssh2). Designed to be pluggable for future transports (local shell, Docker exec, etc.).

```typescript
interface TerminalTransport extends EventEmitter {
  write(data: string): void;
  resize(cols: number, rows: number): void;
  close(): void;
  // Events: "data", "close", "error"
}
```

### SshTransportFactory (`src/transport/ssh-transport-factory.ts`)

Resolves endpoint configuration and key material to establish SSH connections. Supports three authentication modes:

1. **File key** — auto-sign with a PEM key from the key directory (no user interaction)
2. **Passkey** — browser-based WebAuthn signing via the signing bridge
3. **Auto-negotiate** — tries all available keys (file keys first, then passkeys)

For admin accounts, auto-negotiate uses `CompositeSshAgent` (file keys + passkeys). For non-admin accounts, `WebAuthnSshAgent` (passkeys only).

### SshTransport (`src/transport/ssh-transport.ts`)

ssh2-based implementation of `TerminalTransport`. Connects to a remote host, authenticates via private key or WebAuthn agent, allocates a PTY, and opens an interactive shell.

- PTY: xterm-256color, 80x24 default
- Connection timeout: 10 seconds
- Resize via `setWindow()`
- Handles unexpected disconnects gracefully

### KeyDirectoryWatcher (`src/transport/key-directory-watcher.ts`)

Watches the key directory for SSH private key files. Auto-discovers keys on startup and monitors for changes (additions, removals, modifications).

- Scans for `.pem` files, extracts fingerprints and public keys
- Provides `PrivateKeyProvider` interface for runtime key lookup by fingerprint
- Registers discovered keys in the database via `SshKeyRepository`

## Authentication & WebAuthn

### WebAuthn / Passkeys (`src/webauthn/`)

ShellWatch uses WebAuthn passkeys (e.g., YubiKeys, platform authenticators) for both user authentication and SSH key signing.

**Key types:**

- `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` — custom OpenSSH algorithm for browser-registered FIDO2 credentials
- Standard file-based keys (ed25519, RSA, ECDSA) — auto-sign, no user interaction

**Components:**

| File                     | Purpose                                                                       |
| ------------------------ | ----------------------------------------------------------------------------- |
| `ssh-agent.ts`           | `WebAuthnSshAgent` — custom ssh2 agent that delegates signing via callbacks   |
| `composite-ssh-agent.ts` | `CompositeSshAgent` — extends WebAuthnSshAgent with file key approval support |
| `signing-bridge.ts`      | `SigningBridge` — converts raw sign callbacks into `PendingAction` records    |
| `signature-format.ts`    | Converts WebAuthn assertions to SSH signature wire format (PROTOCOL.u2f)      |
| `ssh-key-format.ts`      | Converts COSE public keys to OpenSSH authorized_keys format                   |
| `routes.ts`              | WebAuthn registration and authentication HTTP routes                          |

Approval flow (passkey signing, file-key approval) is decoupled from the browser connection via the **PendingAction** system — see the [PendingAction & Sign Requests](#pendingaction--sign-requests-srcpending-action) section below.

### PendingAction & Sign Requests (`src/pending-action/`)

Unified approval system for all human-in-the-loop interactions (passkey signing, file-key approval). Decouples sign requests from the browser's live WebSocket — an approver can be notified via WebSocket toast, Web Push, or any future channel, and can approve from any browser (or phone) that's authenticated to the account.

**Components:**

| File              | Purpose                                                                                   |
| ----------------- | ----------------------------------------------------------------------------------------- |
| `types.ts`        | `SignRequestContext` discriminated union + `PendingAction` record shape                   |
| `store.ts`        | `PendingActionStore` — in-memory TTL map (60s) with resolve/deny/expire                   |
| `dispatcher.ts`   | `NotificationDispatcher` — fans the action out to registered `NotificationChannel`s       |
| `ws-channel.ts`   | `WebSocketChannel` — sends `sign:request` / `sign:resolved` to connected account browsers |
| `push-channel.ts` | `PushChannel` — Web Push notifications (when a browser isn't open / visible)              |

**Sign request sources** — `SignRequestContext` is a discriminated union:

| Source             | When                                                                         | Key fields                                                                                        |
| ------------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `endpoint-auth`    | ShellWatch's own SSH client auth to an endpoint (UI- or MCP-triggered)       | `endpointLabel`, `endpointAddress`, `trigger: { kind: "ui" \| "mcp" }`                            |
| `agent-forwarding` | Downstream `auth-agent@openssh.com` channel from a running session           | `endpointLabel`, `endpointAddress`, `sessionId` of parent session                                 |
| `agent-proxy`      | Remote `shellwatch-agent` Go client requesting a sign over `/agent-proxy` WS | `sourceIp`, the requesting OAuth client's label + id prefix, optional `clientHostname/OS/Version` |

Client-reported fields on `agent-proxy` (hostname/OS/version from `X-ShellWatch-*` handshake headers) and MCP client name/version on `endpoint-auth` triggers are shown in a separate "self-reported" block on `/sign/:id` so approvers don't mistake spoofable data for authoritative identity.

**Approval flow:**

```
1. Agent's sign() fires onSignRequest callback with resolve/reject closures
2. SigningBridge creates a PendingAction in the store (optional redirectTo)
3. NotificationDispatcher fans out to all channels (WS + Push)
4. Approver opens /sign/:id — GET /api/actions/:id returns the action
5. For agent-forwarding, the page also fetches /api/sessions/:id/tail to
   show the parent session's current output (pre-approval context)
6. User approves → POST /api/actions/:id/resolve (with WebAuthn assertion
   payload for webauthn-sign, empty body for key-approve)
7. Store.resolve() fires the stored resolve callback → ssh2 gets signature
8. Browser navigates to redirectTo (e.g. /session/<new-session-id>)
```

Actions expire after 60s if no response; denied/expired actions surface back to ssh2 as a sign failure. WebSocket `sign:resolved` broadcasts clear toasts on any other tabs open for the account.

### Account System (`src/db/repositories/account-repo.ts`)

- Admin account (single, created on first passkey registration)
- Non-admin accounts (created via WebAuthn registration)
- Passkey-first authentication — no passwords
- Inactive account cleanup (90+ days, admin exempt)

### OAuth2 / OIDC — fully delegated to Ory Hydra (`src/hydra/`)

ShellWatch runs **no OAuth logic of its own** — [Ory Hydra](https://www.ory.sh/hydra/) is the single OAuth2/OIDC authority for every client (web UI, MCP, agent). ShellWatch is Hydra's **passkey-gated login + consent provider** and verifies the bearer tokens Hydra issues; it never sees a password and stores no client secrets or API keys.

- **One flow for everyone:** mediated Dynamic Client Registration (`POST /oauth2/register`) → `authorization_code` + PKCE → passkey login + consent. The access token's `sub` is the ShellWatch account (the human who logged in); an OAuth client is never bound to an account, and the granted `scope` (`ui` / `mcp` / `agent`) selects the surface.
- **Single bearer gate** (`src/server/auth/bearer-gate.ts`): every authenticated surface presents an opaque Hydra access token, introspected per request (RFC 7662) and authorized by path — `ui` for `/api/*` + `/ws`, `mcp` for `/mcp`, `agent` for `/agent-proxy`. Only access tokens are honored (`token_use`); introspection fails closed (errors → 401, never cached).
- **Tokens, not cookies:** the web UI is a public PKCE client holding its tokens in the browser (access token in memory, rotating refresh token in `localStorage`). No server-side session, no session cookie, no API keys.
- **Components** (`src/hydra/`): `routes.ts` (passkey login/consent/logout providers, mediated DCR, RFC 9728/8414 discovery), `admin-client.ts` (Hydra admin API), `bearer-resolver.ts` (cached introspection), `ensure-client.ts` (provisions the first-party SPA client on boot), `render.ts` (server-rendered passkey pages). Hydra itself runs as a separate service backed by its own SQLite DB (`./data/hydra.sqlite`).

## Client Interfaces

### Web UI (`client/`)

SvelteKit SPA (adapter-static) served as static files by Fastify. SvelteKit provides client-side routing, layouts, and the build pipeline — but no server-side features (no SSR, no API routes, no server hooks). All server logic lives in Fastify. The UI uses xterm.js for terminal emulation and Svelte stores for reactive state management.

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

- **REST API** (`/api/*`) — endpoint/session/key/WebAuthn CRUD, action resolve/deny (`/api/actions/:id/resolve` & `/deny`), session tail (`/api/sessions/:id/tail`)
- **WebSocket** (`/ws`) — real-time terminal I/O and session events; also carries `sign:request` / `sign:resolved` notifications from the PendingAction system

**WebSocket protocol (`src/server/ws-protocol.ts`):**

```
Client → Server: terminal:attach, terminal:input, terminal:resize, terminal:close,
                 terminal:take-control, terminal:release-control
Server → Client: terminal:output, terminal:status, terminal:closed, terminal:mode,
                 sessions:changed, error
```

`sign:request` and `sign:resolved` also flow over the same WebSocket but are sent by `WebSocketChannel` in the PendingAction layer (`src/pending-action/ws-channel.ts`), not by the core terminal protocol — that's why they don't appear in `ws-protocol.ts`.

Sign approval itself (resolve/deny with WebAuthn assertion payload) goes over REST, not the WebSocket — see the [PendingAction section](#pendingaction--sign-requests-srcpending-action).

**WebSocket extensions (`src/server/ws-extension.ts`):** Pluggable interface for sending server-initiated messages to account-scoped browser connections. `WebSocketChannel` (the notification-dispatcher channel) implements it to broadcast `sign:request` / `sign:resolved` to tabs owned by the target account.

**State management:** Svelte stores provide reactive state shared across components:

- `ws.ts` — WebSocket connection, message dispatch, session list
- `endpoints.ts` — endpoint CRUD operations
- `keys.ts` — SSH keys
- `webauthn.ts` — passkey registration, login, credential management
- `connection.ts` — base path configuration

**Layout:** Responsive — persistent sidebar (280px) on desktop, hamburger slide-out on mobile (<768px). Settings uses a tab bar for sub-routes.

The web UI sees ALL sessions (admin view) regardless of source. Sessions are displayed with their source label (`ui`, `mcp`, `ssh`).

**Session lifecycle events:** The server broadcasts `sessions:changed` to all connected WebSocket clients whenever any session's status changes, enabling real-time updates across tabs and across sources (MCP-created sessions appear in the UI instantly).

### MCP Server (`src/mcp/`)

Streamable HTTP MCP endpoint at `/mcp`. Each MCP client connection gets its own stateful transport (per the MCP spec for streamable HTTP). Requires an OAuth bearer token with the `mcp` scope (Hydra-issued; see [OAuth2 / OIDC](#oauth2--oidc--fully-delegated-to-ory-hydra-srchydra)).

**Tools:**
| Tool | Description |
|------|-------------|
| `shellwatch_create_session` | Create a terminal session |
| `shellwatch_list_sessions` | List this agent's sessions |
| `shellwatch_send_keys` | Send keystrokes/text to a session |
| `shellwatch_read_output` | Read session output (with offset) |
| `shellwatch_close_session` | Close a session |
| `shellwatch_manage_endpoints` | List, create, update, or delete SSH endpoints |
| `shellwatch_manage_keys` | List available SSH keys |

**Notifications (server → client):**
| Notification | When | Contains |
|-------------|------|----------|
| `output_available` | New output after debounce | `sessionId`, `offset` |
| `session_status` | Session status changed | `sessionId`, `status`, `endpointId` |

Notifications are debounced (configurable `debounceMs`, default 100ms) and scoped to the agent's own sessions.

**Session lifecycle:** MCP client connection creates an `AgentSession`. When the MCP transport disconnects, `AgentSession.destroy()` closes all owned terminal sessions.

### SSH Agent Proxy (`src/agent-socket/`)

WebSocket endpoint at `/agent-proxy` that bridges the SSH agent protocol for remote clients. A thin Go client ([`shellwatch-agent`](../agent-client/)) on the user's workstation relays SSH agent protocol frames over WebSocket.

**Components:**

| File                      | Purpose                                                        |
| ------------------------- | -------------------------------------------------------------- |
| `agent-proxy-route.ts`    | WebSocket endpoint — auth, credential lookup, protocol wiring  |
| `socket-agent-handler.ts` | Builds `CompositeSshAgent` and wires to ssh2's `AgentProtocol` |

**Flow:**

```
ssh client → Unix socket → shellwatch-agent (Go) → WSS → ShellWatch /agent-proxy
                                                          │
                                                          ├─ file keys (auto-sign)
                                                          └─ passkeys (browser-signed via WebAuthn)
```

- Each WebSocket connection gets its own `AgentProtocol` instance
- Both passkey signs _and_ file-key uses create `PendingAction`s for approval (no silent file-key auto-sign on this path — the whole point is human-in-the-loop)
- Requires an OAuth bearer token with the `agent` scope (Hydra-issued)
- Requires OpenSSH 10.3+ on the client for passkey support (see [#36](https://github.com/rado0x54/ShellWatch/issues/36))
- Client advertises `X-ShellWatch-Hostname` / `-OS` / `-Version` handshake headers so the approver can see which machine is asking (sanitized server-side, rendered as "self-reported")

**OpenSSH 10.3 canonicalization:** OpenSSH canonicalizes `webauthn-sk-ecdsa` to `sk-ecdsa` in agent protocol messages. The ssh2 fork handles this by checking the key's application field (`"ssh:"` = standard FIDO2, web domain = webauthn) and using the correct PROTOCOL.u2f wire format in `signReply`. See [rado0x54/ssh2#1](https://github.com/rado0x54/ssh2/pull/1).

## Agent Layer (`src/agent/`)

### AgentSession (`src/agent/agent-session.ts`)

Manages terminal sessions owned by a single agent connection. Enforces session isolation — each agent can only see and interact with sessions it created.

```typescript
class AgentSession {
  createSession(endpointId: string): Promise<TerminalSession>;
  listSessions(): TerminalSession[]; // only owned sessions
  sendKeys(sessionId: string, keys: string[]): void;
  readOutput(sessionId: string, afterOffset?, limit?): OutputReadResult;
  closeSession(sessionId: string): void;
  destroy(): void; // close all owned sessions
}
```

**Used by:**

- MCP server — one `AgentSession("mcp")` per MCP client connection
- SSH server (planned) — one `AgentSession("ssh")` per SSH client connection

**Not used by the web UI** — the UI uses the REST API and WebSocket which operate directly on the TerminalManager (admin-level access, sees all sessions).

## Persistence (`src/db/`)

### SQLite Database

Single-file database (`data/shellwatch.db`) via better-sqlite3 with Drizzle ORM. WAL mode for concurrent reads.

**Schema (`src/db/schema.ts`):**

| Table                     | Purpose                                                                            |
| ------------------------- | ---------------------------------------------------------------------------------- |
| `accounts`                | User/agent accounts (admin flag, session limits, last used)                        |
| `admin_account`           | Single-row pointer table identifying the admin account                             |
| `webauthn_credentials`    | Passkey credentials (COSE public key, OpenSSH public key, label)                   |
| `ssh_keys`                | File-based SSH key metadata (fingerprint, public key — private keys on filesystem) |
| `endpoints`               | SSH target configuration (host, port, username, key/passkey assignment)            |
| `audit_session_lifecycle` | Tamper-evident session audit log (open/close events, source, timestamps)           |
| `audit_signing_requests`  | Signing-request audit log (passkey signs, key approvals — outcomes + metadata)     |
| `push_subscriptions`      | Web Push subscriptions per account (endpoint, auth/p256dh keys)                    |

**Repositories (`src/db/repositories/`):**

| Repository              | Scope                                                 |
| ----------------------- | ----------------------------------------------------- |
| `account-repo.ts`       | Account CRUD, admin check, activity tracking, cleanup |
| `endpoint-repo.ts`      | Endpoint CRUD with key/passkey assignment             |
| `key-repo.ts`           | SSH key registration and lookup                       |
| `credential-queries.ts` | WebAuthn credential lookup for signing                |

OAuth clients, tokens, and consent/login sessions are **not** stored here — they live in Hydra. ShellWatch only verifies Hydra-issued tokens (via introspection) and reads Hydra's consent sessions through the admin API.

**Migrations:** Auto-run at startup from `drizzle/` directory.

## Audit Log (`src/audit/`)

Tamper-evident, append-only audit of session lifecycle and signing-request outcomes. The audit module subscribes to `TerminalManager` events and `PendingActionStore` resolutions; it never joins to live tables at read time, so a passkey rename or endpoint relabel never rewrites history.

| File                          | Purpose                                                                                                                                       |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `session-lifecycle-writer.ts` | Subscribes to TerminalManager open/close events, persists to `audit_session_lifecycle`                                                        |
| `session-lifecycle-repo.ts`   | Keyset-paged read API powering `/audit/sessions`                                                                                              |
| `signing-requests-writer.ts`  | Persists every PendingAction outcome (`approved` / `denied` / `expired` / `cancelled`) to `audit_signing_requests` with full trigger metadata |
| `signing-requests-repo.ts`    | Read API powering `/audit/signings`                                                                                                           |

All audit reads are account-scoped — admin is an admin role, not a global view across accounts.

## Security

### IP Allowlist (`src/server/auth/ip-allowlist.ts`)

CIDR-based network filter applied to MCP and agent proxy endpoints. Configured via `security.allowedNetworks` in config. Defaults to localhost only (`127.0.0.1/32`, `::1/128`).

Handles IPv4, IPv6, and IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`).

### Bearer Gate (`src/server/auth/bearer-gate.ts`)

The single authentication gate for every protected surface (`/api/*`, `/ws`, `/mcp`, `/agent-proxy`). It extracts the Hydra access token (the `Authorization: Bearer` header, or the `Sec-WebSocket-Protocol` subprotocol on `/ws` — browsers can't set headers on a WS handshake), introspects it via `bearer-resolver.ts` (RFC 7662, cached), and authorizes by path/scope (`ui` / `mcp` / `agent`). Only access tokens pass; introspection failures fail closed. There is no session cookie and no API-key path — all auth is Hydra-issued OAuth bearer tokens. See [OAuth2 / OIDC](#oauth2--oidc--fully-delegated-to-ory-hydra-srchydra).

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
  port: 3000 # HTTP port
  externalUrl: http://localhost:3000 # required — issuer/redirect base for OAuth

hydra: # OAuth2/OIDC authority (required)
  publicUrl: http://localhost:4444 # Hydra public issuer
  adminUrl: http://localhost:4445 # Hydra admin API (trusted-network only)
  spa:
    clientId: shellwatch-web # first-party PKCE client (no secret)

agentSocket:
  proxyEnabled: true # Enable /agent-proxy WebSocket endpoint

notifications:
  mcp:
    debounceMs: 100 # output_available debounce

# Seeding (first run only)
seedAdminEndpoints: # Pre-seed SSH endpoints
  - label: Dev Box
    address: ubuntu@dev.example.com
seedAdminPasskeys: # Pre-seed admin passkeys (for testing)
  - credentialId: base64url...
    publicKeyHex: hex...
```

Config is validated at startup via Zod. See `config.sample.yaml` for all options.

## Process Model

Everything runs in a single Node.js process:

```
┌─────────────────────────────────────────┐
│              Node.js Process            │
│                                         │
│  Fastify HTTP server (:3000)            │
│    ├── REST API routes (/api/*)         │
│    ├── WebSocket handler (/ws)          │
│    ├── MCP streamable HTTP (/mcp)       │
│    ├── Agent proxy WebSocket            │
│    │   (/agent-proxy)                   │
│    ├── WebAuthn routes (/api/webauthn)  │
│    ├── Health check (/health)           │
│    └── Static files (/ — SvelteKit SPA) │
│                                         │
│  TerminalManager                        │
│    └── SSH connections (ssh2)           │
│                                         │
│  SigningBridge + PendingActionStore       │
│    └── Approval queue (60s TTL)         │
│                                         │
│  NotificationDispatcher                 │
│    └── WebSocket + Web Push channels    │
│                                         │
│  KeyDirectoryWatcher                    │
│    └── SSH key auto-discovery           │
│                                         │
│  SQLite (better-sqlite3, WAL mode)      │
│                                         │
└─────────────────────────────────────────┘
```

## Data Flow Examples

### Agent runs a command via MCP

```
1. MCP client calls shellwatch_send_keys(sessionId, ["text:ls -la", "enter"])
2. AgentSession.sendKeys() checks ownership → resolves key names to bytes
3. TerminalManager.sendInput() writes to SshTransport
4. SshTransport.write() sends bytes to remote shell via ssh2
5. Remote shell executes, output flows back via ssh2 stream
6. SshTransport emits "data" → TerminalManager appends to OutputBuffer
7. TerminalManager emits "output" event
8. MCP notification dispatcher (debounced) sends output_available notification
9. WebSocket handler broadcasts to attached UI clients (terminal:output)
10. MCP client calls shellwatch_read_output(sessionId, afterOffset)
11. AgentSession.readOutput() checks ownership → reads from OutputBuffer
```

### Session created via MCP appears in web UI

```
1. MCP client calls shellwatch_create_session(endpointId)
2. AgentSession.createSession() → TerminalManager.create()
3. TerminalManager establishes SSH connection
4. TerminalManager emits status-change("open")
5. WebSocket handler broadcasts sessions:changed to all browser clients
6. Browser renders new session in sidebar with "(mcp)" label
7. Browser user clicks session → terminal:attach → receives buffered output
```

### SSH via agent proxy with passkey signing

```
1. ssh client connects to shellwatch-agent Unix socket
2. shellwatch-agent opens WSS to ShellWatch /agent-proxy
   (advertises X-ShellWatch-Hostname / -OS / -Version headers)
3. SSH client sends SSH_AGENTC_REQUEST_IDENTITIES
4. AgentProtocol returns file keys + passkeys
5. SSH client sends SSH_AGENTC_SIGN_REQUEST for a passkey
6. CompositeSshAgent delegates to WebAuthnSshAgent
7. WebAuthnSshAgent's onSignRequest → SigningBridge creates a PendingAction
   with an agent-proxy context (OAuth client label, client metadata)
8. NotificationDispatcher fans out to connected browsers (sign:request via WS)
   and/or Web Push; user sees a toast and/or native push notification
9. User opens /sign/:id, taps passkey → WebAuthn ceremony in browser
10. Browser POSTs the assertion to /api/actions/:id/resolve
11. SigningBridge's resolve callback hands the signature back to ssh2
12. Signature returned to SSH client via agent proxy
13. SSH client authenticates with remote server
```

## File Structure

```
src/
  index.ts                      # Entry point — config, TerminalManager, Fastify
  agent/
    agent-session.ts            # Session ownership and isolation per agent
  agent-socket/
    agent-proxy-route.ts        # WebSocket endpoint for SSH agent proxy
    socket-agent-handler.ts     # AgentProtocol wiring to CompositeSshAgent
  audit/
    session-lifecycle-writer.ts # Subscribes to TerminalManager, persists open/close events
    session-lifecycle-repo.ts   # Read API for /audit/sessions
    signing-requests-writer.ts  # Persists PendingAction outcomes (approve/deny/expire/cancel)
    signing-requests-repo.ts    # Read API for /audit/signings
  config/
    schema.ts                   # Zod schemas for config validation
    loader.ts                   # YAML config loading
  db/
    connection.ts               # SQLite connection setup
    schema.ts                   # Drizzle table definitions
    repositories/               # Data access layer (accounts, keys, endpoints, etc.)
  hydra/
    routes.ts                   # Passkey login/consent/logout providers, mediated DCR, discovery
    admin-client.ts             # Ory Hydra admin API client
    bearer-resolver.ts          # Cached RFC 7662 token introspection
    ensure-client.ts            # Provisions the first-party SPA client on boot
    render.ts                   # Server-rendered passkey login/consent pages
  server/
    app.ts                      # Fastify app — routes, WebSocket, MCP, static files
    ws-handler.ts               # WebSocket protocol handler
    ws-extension.ts             # Pluggable WS message interceptor interface
    ws-protocol.ts              # WebSocket message type definitions
    auth/
      bearer-gate.ts            # Single OAuth bearer gate (introspects Hydra tokens)
      ip-allowlist.ts           # CIDR-based IP filtering
  terminal/
    terminal-manager.ts         # Central session registry and lifecycle
    output-buffer.ts            # Append-only output buffer with offsets
    transport.ts                # TerminalTransport interface
    keys.ts                     # Named key → escape sequence mapping
    types.ts                    # TerminalSession, status, events
  transport/
    ssh-transport.ts            # ssh2 implementation of TerminalTransport
    ssh-transport-factory.ts    # Resolves auth mode (file key / passkey / auto)
    key-directory-watcher.ts    # Filesystem key discovery and watching
    key-scanner.ts              # PEM key parsing and fingerprinting
  mcp/
    server.ts                   # MCP tool definitions (delegates to AgentSession)
    http-transport.ts           # Streamable HTTP transport wiring
    notifications.ts            # Debounced MCP notification dispatcher
  pending-action/
    types.ts                    # SignRequestContext union + PendingAction record
    store.ts                    # In-memory TTL store with resolve/deny/expire
    dispatcher.ts               # Fans actions out to NotificationChannels
    ws-channel.ts               # sign:request / sign:resolved over WebSocket
    push-channel.ts             # Web Push delivery
  webauthn/
    ssh-agent.ts                # WebAuthnSshAgent — browser-delegated signing
    composite-ssh-agent.ts      # CompositeSshAgent — file keys + passkeys
    signing-bridge.ts           # SigningBridge — agent ↔ browser relay
    signature-format.ts         # WebAuthn → SSH signature conversion
    ssh-key-format.ts           # COSE → OpenSSH key format conversion
    routes.ts                   # WebAuthn registration/auth HTTP routes
  test/
    helpers/                    # In-process test infrastructure
    integration/                # End-to-end tests across all actors
client/                           # SvelteKit frontend (adapter-static)
  src/
    app.html                    # HTML shell
    app.css                     # Global styles (CSS variables, shared classes)
    lib/
      stores/                   # Svelte stores (ws, endpoints, keys, webauthn, toasts, account, ...)
      components/               # Reusable components (Terminal, TerminalSnapshot, Sidebar, ToastContainer, Identicon)
      utils/                    # Utilities (WebAuthn ceremony helpers, error formatting)
    routes/
      +layout.svelte            # Root layout (sidebar + mobile nav + auth gate)
      +page.svelte              # Terminal view (default route)
      session/[id]/             # Specific session view
      sign/[id]/                # Sign-request approval page (+ tail preview for agent-forwarding)
      auth/callback/            # OAuth redirect target — exchanges code for tokens
      register/                 # WebAuthn passkey registration (bootstrap / self-register)
      observer/                 # Multi-session grid view
      audit/                    # Audit log views (sessions / signings)
      admin/                    # Admin views (accounts, general settings)
      passkey-invite/[token]/   # Cross-device passkey enrollment
      settings/                 # Settings with tab sub-routes (incl. notifications / Web Push)
  svelte.config.js              # SvelteKit config (adapter-static)
agent-client/                     # Go thin client for SSH agent proxy
  cmd/shellwatch-agent/         # CLI entry point
  internal/
    config/                     # Flag/env config parsing
    proxy/                      # WebSocket relay + SSH agent protocol
```

## Planned Architecture Extensions

See individual tickets for details:

- **Guardrails (#13)** — input filtering layer in TerminalManager, before `sendInput()`
- **SSH Server (#12)** — ssh2 Server for agent SSH access, username-based routing, uses AgentSession
- **Telegram notification channel** — new `NotificationChannel` implementation alongside WS/Push
- **Agent client distribution (#35)** — Homebrew tap published at [rado0x54/homebrew-tap](https://github.com/rado0x54/homebrew-tap); still pending: install script, deb/rpm packaging, install-service CLI; Windows support in #175
