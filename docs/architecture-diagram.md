# ShellWatch — Architecture Diagram

High-level functional architecture showing the primary actors and their interactions.

```mermaid
graph TB
    subgraph Clients
        User["User (Human)<br/>SvelteKit SPA + xterm.js"]
        Agent["Agent (AI)<br/>MCP Client"]
        SSHCli["SSH Client<br/>ssh, scp, git"]
    end

    subgraph ShellWatch["ShellWatch Server"]
        WebUI["Web UI Server<br/><i>REST /api/* + WebSocket /ws</i>"]
        MCP["MCP Server<br/><i>Streamable HTTP /mcp</i>"]
        AgentProxy["Agent Proxy<br/><i>WebSocket /agent-proxy</i>"]
        AS["AgentSession<br/><i>Per-agent isolation</i>"]
        TM["TerminalManager<br/><i>Central session registry</i>"]
        SB["SigningBridge<br/><i>WebAuthn relay</i>"]
        STF["SshTransportFactory<br/><i>File keys + passkeys</i>"]
        SSH["SSH Transport<br/><i>ssh2 library</i>"]
        KDW["KeyDirectoryWatcher<br/><i>Auto-discovery</i>"]
        DB["SQLite<br/><i>Drizzle ORM</i>"]

        MCP --> AS
        AS --> TM
        WebUI --> TM
        TM --> STF
        STF --> SSH
        STF --> SB
        AgentProxy --> SB
        KDW --> STF
        WebUI --> DB
        MCP --> DB
        AgentProxy --> DB
    end

    subgraph Targets["Target Servers"]
        Remote["Remote SSH Host<br/><i>Interactive PTY / Shell</i>"]
    end

    User -- "REST API (CRUD)<br/>WebSocket (terminal I/O, events)<br/>WebAuthn (passkey signing)" --> WebUI
    Agent -- "MCP over HTTP<br/>(create, send_keys, read_output)<br/>API key auth" --> MCP
    SSHCli -- "shellwatch-agent (Go)<br/>SSH agent protocol over WSS<br/>API key auth" --> AgentProxy
    SSH -- "SSH (key or passkey auth)" --> Remote

    SB -. "fido:sign-request /<br/>fido:sign-response" .-> User
    TM -. "events: output,<br/>status-change, close" .-> WebUI
    TM -. "events (debounced<br/>notifications)" .-> MCP
```

## Actor Roles

| Actor             | Protocol                          | Access Level          | Description                                                                                                                                                                                                            |
| ----------------- | --------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **User**          | REST + WebSocket + WebAuthn       | Admin (all sessions)  | Browser-based terminal UI. Sees all sessions regardless of source. Handles WebAuthn signing for passkey-based SSH auth.                                                                                                |
| **Agent**         | MCP (HTTP)                        | Scoped (own sessions) | AI agent connecting via MCP. Each agent gets an isolated `AgentSession` and can only see/control sessions it created. Requires API key with `mcp` scope.                                                               |
| **SSH Client**    | SSH agent protocol (via Go proxy) | Key-based             | System SSH clients (`ssh`, `scp`, `git`) using ShellWatch-managed keys via the agent proxy. Supports file keys (auto-sign) and passkeys (browser-signed, requires OpenSSH 10.3+). Requires API key with `agent` scope. |
| **ShellWatch**    | &mdash;                           | &mdash;               | Session broker. Routes input/output, buffers terminal data, broadcasts events, enforces isolation between agents, manages key material and WebAuthn signing.                                                           |
| **Target Server** | SSH                               | &mdash;               | Remote host accessed via ssh2 with key-based or WebAuthn passkey auth and PTY allocation.                                                                                                                              |

## Data Flow — MCP Session

```mermaid
sequenceDiagram
    participant A as Agent
    participant SW as ShellWatch
    participant T as Target Server
    participant U as User (Browser)

    A->>SW: create_session(endpoint)
    SW->>T: SSH connect (key auth + PTY)
    T-->>SW: Connection established
    SW-->>A: session created
    SW-->>U: sessions:changed (WebSocket)

    A->>SW: send_keys(sessionId, "ls -la")
    SW->>T: write bytes to SSH stream
    T-->>SW: command output (SSH stream)
    SW-->>U: terminal:output (WebSocket)
    SW-->>A: output_available (MCP notification)
    A->>SW: read_output(sessionId, afterOffset)
    SW-->>A: buffered output

    U->>SW: terminal:input (WebSocket)
    SW->>T: write bytes to SSH stream
    T-->>SW: command output
    SW-->>U: terminal:output (WebSocket)
    SW-->>A: output_available (MCP notification)
```

## Data Flow — Agent Proxy with Passkey Signing

```mermaid
sequenceDiagram
    participant SC as SSH Client
    participant GA as shellwatch-agent (Go)
    participant SW as ShellWatch Server
    participant U as User (Browser)
    participant T as Target Server

    SC->>GA: SSH_AGENTC_REQUEST_IDENTITIES
    GA->>SW: relay via WebSocket
    SW-->>GA: file keys + passkeys
    GA-->>SC: identity list

    SC->>GA: SSH_AGENTC_SIGN_REQUEST (passkey)
    GA->>SW: relay via WebSocket
    SW->>U: fido:sign-request (WebSocket)
    Note over U: User touches<br/>security key
    U-->>SW: fido:sign-response (WebAuthn assertion)
    SW-->>GA: SSH signature (PROTOCOL.u2f format)
    GA-->>SC: signature

    SC->>T: SSH USERAUTH_REQUEST
    T-->>SC: Authentication successful
```
