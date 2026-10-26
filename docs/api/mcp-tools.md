<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# ShellWatch MCP tools (`/mcp`)

Language-agnostic contract for the MCP (Model Context Protocol) surface, frozen
ahead of the Go rewrite (#210, #225). Source of truth in the Node backend:
[`internal/mcp/`](../../internal/mcp/) (`tools_sessions.go`,
`tools_endpoints.go`, the notifier).

## Transport & auth

- Endpoint: `POST/GET /mcp` (MCP streamable HTTP; SSE for server→client).
- Auth scope: `mcp` via `Authorization: Bearer <token>`. Additionally fronted by
  the IP allowlist (`config.security.allowedNetworks`).
- Per-client stateful transport keyed off the MCP session; each agent connection
  gets an isolated `AgentSession` that only sees its own terminal sessions.
- **All tool results are `content: [{ type: "text", text: <JSON string> }]`** —
  the payload is JSON _stringified inside a text block_, not a native structured
  result. Errors are `{ isError: true, content: [{ type:"text", text: <message> }] }`.

## Tools

### `shellwatch_manage_endpoints`

Manage SSH endpoints. Input:

```ts
{ action: "list" | "read" | "create" | "update" | "delete";
  id?: string;                       // required for read/update/delete
  data?: { label?; host?; port?; username?;
           userVerification?: "required" | "preferred" | "discouraged";
           agentForward?: boolean;
           description?: string|null /* ≤1000 chars; null clears */ } }
```

Every REST-editable field is editable here too. `create` defaults:
`userVerification: "required"`, `agentForward: true`, `port: 22`. Invalid
values (unknown `userVerification`, wrong types, over-long `description`)
are rejected without writing. _(Node's tool schema used to silently strip
`userVerification`/`agentForward` — that was a bug, not the contract; both
backends now accept them.)_

**Host keys (#241, Go only):** the agent can neither supply nor alter a host
key pin — `create`/`update` take no host-key fields. `read` returns a
read-only `hostKey` object (`{ type, fingerprint, pinnedAt, pinnedBy }`, or
`null` when unpinned). **Updating `host` or `port` clears the pin** (the old
key cannot vouch for a new address) and writes a `host-key-cleared` audit
row; the next `shellwatch_create_session` then blocks on a human approving
the new host's key.

Per-action success payload (JSON in the text block):

- `list` → `{ endpoints: [{ id, label, host, port, username, description }] }`
  _(note: no `userVerification`/`agentForward`/`isDemo` — narrower than REST)_
- `read` → the raw endpoint object (incl. the read-only `hostKey`, Go only)
- `create` → `{ status: "created", id }` — **`id` is caller-supplied and required**
  _(diverges from REST `POST /api/endpoints`, which generates a UUID)_
- `update` → `{ status: "updated", id }`
- `delete` → `{ status: "deleted", id }`

Demo endpoints (`demo:*`) are read-only: create/update/delete return `isError`.

### `shellwatch_create_session`

Input: `{ endpointId: string; reason: string /* ≤500, non-empty, trimmed */ }`.
`reason` is shown to the human approver. Success →
`{ sessionId, endpointId, status }`. _(No `createdAt`/`source` — narrower than the
REST/WS session object.)_

Host-key errors (#241, Go only) surface as the usual `isError` text:

- **Untrusted first connection** (human denied / prompt expired on an
  unpinned endpoint): the error ends with
  `the host key for this endpoint is not trusted yet; a human must approve the
first connection on the ShellWatch sign page` — direct the user to the
  ShellWatch UI; there is nothing the agent can retry on its own.
- **Host-key mismatch** (pinned key differs from what the server presented):
  a distinct error starting `SSH connection to <addr> refused: host key
mismatch: …`. The connection was aborted before authentication and **no
  retry path exists over MCP** — only a human can forget the pinned key in
  Settings → Endpoints.

### `shellwatch_list_sessions`

Input: `{}`. Success → `{ sessions: [{ sessionId, endpointId, status, createdAt }] }`.

### `shellwatch_send_keys`

Input: `{ sessionId: string; keys: string[] }`. Keys are named
(`SUPPORTED_KEYS`) or `text:<content>` for literal text. Success →
`{ status: "sent", keys }`.

### `shellwatch_read_output`

Input: `{ sessionId: string; afterOffset?: number; limit?: number /* default 4000 */ }`.
Success → `OutputReadResult`: `{ data: string, offset: number, hasMore: boolean }`.
_(Note: `hasMore` here vs. WS `terminal:output`'s `reset` flag — different
buffer-boundary signals for the same ring buffer.)_

### `shellwatch_close_session`

Input: `{ sessionId: string }`. Success → `{ status: "closed" }`.
(Close reason recorded as `client.mcp`.)

### `shellwatch_manage_keys`

Input: `{ action: "list" | "read"; id?: string }`.

- `list` → `{ keys: [{ id, label, type, fingerprint }] }`
- `read` → `{ id, label, type, fingerprint, publicKey }`

## Notifications (server → client)

Debounced, per subscribed session (`internal/mcp`). `params`:

- `notifications/shellwatch/output_available` — new output is buffered.
  `params: { sessionId: string, offset: number }` (current buffer offset).
- `notifications/shellwatch/session_status` — session status changed.
  `params: { sessionId: string, status: string, endpointId?: string }`
  (`endpointId` is omitted if the session is already gone).

## REST ↔ MCP divergences to reconcile (see #225)

| Concern              | REST                                               | MCP                                              |
| -------------------- | -------------------------------------------------- | ------------------------------------------------ |
| Endpoint create `id` | server generates UUID                              | **caller supplies `id`**                         |
| Endpoint fields      | incl. `userVerification`, `agentForward`, `isDemo` | omits all three                                  |
| Session object       | full `TerminalSession`                             | `{ sessionId, endpointId, status(, createdAt) }` |
| Output boundary flag | WS `reset`                                         | `hasMore`                                        |
| Result shape         | native JSON body                                   | JSON **stringified** in a text block             |

The Go rewrite should decide per row whether to preserve the divergence (and
document it) or converge — but not change it silently.
