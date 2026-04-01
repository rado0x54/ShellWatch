# ShellWatch — Architecture Diagram

High-level functional architecture showing the four primary actors and their interactions.

```mermaid
graph TB
    subgraph Clients
        User["User (Human)<br/>SvelteKit SPA + xterm.js"]
        Agent["Agent (AI)<br/>MCP Client"]
    end

    subgraph ShellWatch["ShellWatch Server"]
        WebUI["Web UI Server<br/><i>REST /api/* + WebSocket /ws</i>"]
        MCP["MCP Server<br/><i>Streamable HTTP /mcp</i>"]
        SSHSrv["SSH Server (planned #12)<br/><i>ssh2 Server :2222</i>"]
        AS["AgentSession<br/><i>Per-agent isolation</i>"]
        TM["TerminalManager<br/><i>Central session registry</i>"]
        SSH["SSH Transport<br/><i>ssh2 library</i>"]

        MCP --> AS
        SSHSrv --> AS
        AS --> TM
        WebUI --> TM
        TM --> SSH
    end

    subgraph Targets["Target Servers"]
        Remote["Remote SSH Host<br/><i>Interactive PTY / Shell</i>"]
    end

    User -- "REST API (CRUD)<br/>WebSocket (terminal I/O, events)" --> WebUI
    Agent -- "MCP over HTTP<br/>(create, send_keys, read_output)" --> MCP
    Agent -. "SSH (planned #12)<br/>username-based routing" .-> SSHSrv
    SSH -- "SSH (key-based auth)" --> Remote

    TM -. "events: output,<br/>status-change, close" .-> WebUI
    TM -. "events (debounced<br/>notifications)" .-> MCP
```

## Actor Roles

| Actor | Protocol | Access Level | Description |
|-------|----------|-------------|-------------|
| **User** | REST + WebSocket | Admin (all sessions) | Browser-based terminal UI. Sees all sessions regardless of source. Can observe and interact with agent-created sessions in real-time. |
| **Agent** | MCP (HTTP), SSH (planned [#12](https://github.com/user/ShellWatch/issues/12)) | Scoped (own sessions) | AI agent connecting via MCP or SSH. Each agent gets an isolated `AgentSession` and can only see/control sessions it created. |
| **ShellWatch** | &mdash; | &mdash; | Session broker. Routes input/output, buffers terminal data, broadcasts events, enforces isolation between agents. |
| **Target Server** | SSH | &mdash; | Remote host accessed via ssh2 with key-based auth and PTY allocation. |

## Data Flow

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
