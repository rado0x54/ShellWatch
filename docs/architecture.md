ok# ShellWatch Architecture

## Overview

ShellWatch is an SSH session broker that sits between clients (humans and AI agents) and remote SSH targets. All terminal sessions flow through a shared `TerminalManager`, enabling observation, policy enforcement, and audit from a single point.

```
┌─────────────────────────────────────────────────────────┐
│                     ShellWatch                          │
│                                                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│  │ Web UI   │   │ MCP      │   │ SSH Srv  │  (planned) │
│  │ (browser)│   │ (agents) │   │ (agents) │            │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘            │
│       │              │              │                   │
│       │         ┌────┴─────┐   ┌────┴─────┐            │
│       │         │ Agent    │   │ Agent    │             │
│       │         │ Session  │   │ Session  │             │
│       │         └────┬─────┘   └────┬─────┘            │
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
│              │ (ssh2)         │                         │
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

### SshTransport (`src/transport/ssh-transport.ts`)

ssh2-based implementation of `TerminalTransport`. Connects to a remote host, authenticates via private key, allocates a PTY, and opens an interactive shell.

- PTY: xterm-256color, 80x24 default
- Connection timeout: 10 seconds
- Resize via `setWindow()`
- Handles unexpected disconnects gracefully

## Client Interfaces

### Web UI (`client/`)

SvelteKit SPA (adapter-static) served as static files by Fastify. SvelteKit provides client-side routing, layouts, and the build pipeline — but no server-side features (no SSR, no API routes, no server hooks). All server logic lives in Fastify. The UI uses xterm.js for terminal emulation and Svelte stores for reactive state management.

**Routes:**
| Route | View |
|-------|------|
| `/` | Terminal — single active session with xterm.js |
| `/observer` | Observer — multi-session grid (dynamic layout) |
| `/settings/endpoints` | SSH endpoint CRUD |
| `/settings/keys` | SSH key listing |
| `/settings/passkeys` | WebAuthn passkey management |
| `/settings/api-keys` | MCP API key management |
| `/login` | WebAuthn passkey login |

**Communication:**

- **REST API** (`/api/*`) — endpoint listing, session CRUD, key management, WebAuthn
- **WebSocket** (`/ws`) — real-time terminal I/O, session status events, FIDO signing

**WebSocket protocol:**

```
Client → Server: terminal:attach, terminal:input, terminal:resize, terminal:close,
                 terminal:take-control, terminal:release-control,
                 fido:sign-response, fido:sign-error
Server → Client: terminal:output, terminal:status, terminal:closed, terminal:mode,
                 sessions:changed, fido:sign-request, error
```

**State management:** Svelte stores provide reactive state shared across components:

- `ws.ts` — WebSocket connection, message dispatch, session list
- `endpoints.ts` — endpoint CRUD operations
- `keys.ts` — SSH keys and API keys
- `webauthn.ts` — passkey registration, login, credential management
- `connection.ts` — base path configuration

**Layout:** Responsive — persistent sidebar (280px) on desktop, hamburger slide-out on mobile (<768px). Settings uses a tab bar for sub-routes.

The web UI sees ALL sessions (admin view) regardless of source. Sessions are displayed with their source label (`ui`, `mcp`, `ssh`).

**Session lifecycle events:** The server broadcasts `sessions:changed` to all connected WebSocket clients whenever any session's status changes, enabling real-time updates across tabs and across sources (MCP-created sessions appear in the UI instantly).

### MCP Server (`src/mcp/`)

Streamable HTTP MCP endpoint at `/mcp`. Each MCP client connection gets its own stateful transport (per the MCP spec for streamable HTTP).

**Tools:**
| Tool | Description |
|------|-------------|
| `shellwatch_list_endpoints` | List configured SSH endpoints |
| `shellwatch_create_session` | Create a terminal session |
| `shellwatch_list_sessions` | List this agent's sessions |
| `shellwatch_send_keys` | Send keystrokes/text to a session |
| `shellwatch_read_output` | Read session output (with offset) |
| `shellwatch_close_session` | Close a session |

**Notifications (server → client):**
| Notification | When | Contains |
|-------------|------|----------|
| `output_available` | New output after debounce | `sessionId`, `offset` |
| `session_status` | Session status changed | `sessionId`, `status`, `endpointId` |

Notifications are debounced (configurable `debounceMs`, default 100ms) and scoped to the agent's own sessions.

**Session lifecycle:** MCP client connection creates an `AgentSession`. When the MCP transport disconnects, `AgentSession.destroy()` closes all owned terminal sessions.

### SSH Server Interface (planned, #12)

An ssh2 `Server` that allows agents to connect via standard SSH. Username-based endpoint routing (`ssh dev-box@shellwatch:2222`). Creates an `AgentSession("ssh")` per client — same isolation model as MCP.

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

## Security

### IP Allowlist (`src/server/ip-allowlist.ts`)

CIDR-based network filter applied to the MCP endpoint. Configured via `security.allowedNetworks` in config. Defaults to localhost only (`127.0.0.1/32`, `::1/128`).

Handles IPv4, IPv6, and IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`).

### Planned (see tickets)

- API keys for agents (#15)
- Passkey/WebAuthn for admin (#20)
- Guardrails — input filtering (#13)
- Human-in-the-loop approvals (#19)

## Configuration

```yaml
servers: # SSH endpoints
  - id: dev-box
    label: Dev Box
    host: dev.example.com
    port: 22
    username: ubuntu
    privateKeyPath: ./keys/dev-box.pem

security:
  allowedNetworks: # CIDR allowlist for MCP
    - 127.0.0.1/32
    - "::1/128"

notifications:
  mcp:
    debounceMs: 100 # output_available debounce
```

Config is validated at startup via zod. Private key files are verified accessible.

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
│    └── Static files (/ — SvelteKit SPA)  │
│                                         │
│  TerminalManager                        │
│    └── SSH connections (ssh2)           │
│                                         │
│  [Future: ssh2 Server (:2222)]          │
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

## File Structure

```
src/
  index.ts                      # Entry point — config, TerminalManager, Fastify
  agent/
    agent-session.ts            # Session ownership and isolation per agent
  config/
    schema.ts                   # Zod schemas for config validation
    loader.ts                   # YAML config loading and key file verification
  server/
    app.ts                      # Fastify app — routes, WebSocket, MCP, static files
    ws-handler.ts               # WebSocket protocol handler
    ws-protocol.ts              # WebSocket message type definitions
    ip-allowlist.ts             # CIDR-based IP filtering
  terminal/
    terminal-manager.ts         # Central session registry and lifecycle
    output-buffer.ts            # Append-only output buffer with offsets
    transport.ts                # TerminalTransport interface
    keys.ts                     # Named key → escape sequence mapping
    types.ts                    # TerminalSession, status, events
  transport/
    ssh-transport.ts            # ssh2 implementation of TerminalTransport
  mcp/
    server.ts                   # MCP tool definitions (delegates to AgentSession)
    http-transport.ts           # Streamable HTTP transport wiring
    notifications.ts            # Debounced MCP notification dispatcher
  test/
    helpers/                    # In-process test infrastructure
    integration/                # End-to-end tests across all actors
client/                           # SvelteKit frontend (adapter-static)
  src/
    app.html                    # HTML shell
    app.css                     # Global styles (CSS variables, shared classes)
    lib/
      stores/                   # Svelte stores (ws, endpoints, keys, webauthn)
      components/               # Reusable components (Terminal, Sidebar)
      utils/                    # Utilities (FIDO signing)
    routes/
      +layout.svelte            # Root layout (sidebar + mobile nav)
      +page.svelte              # Terminal view (default route)
      login/                    # WebAuthn login page
      observer/                 # Multi-session grid view
      settings/                 # Settings with tab sub-routes
  svelte.config.js              # SvelteKit config (adapter-static)
```

## Planned Architecture Extensions

See individual tickets for details:

- **Guardrails (#13)** — input filtering layer in TerminalManager, before `sendInput()`
- **SSH Server (#12)** — ssh2 Server for agent SSH access, username-based routing, uses AgentSession
- **Audit Log (#16)** — subscribes to TerminalManager events, persists to database
- **Multi-tenant (#17)** — user accounts, agent identities, scoped access
- **Human-in-the-loop (#19)** — Web Push (PWA) notifications and interactive approvals
- **SSH Agent Socket (#22)** — expose keys to system SSH clients via Unix domain socket
