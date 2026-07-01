<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# ShellWatch MCP tools (`/mcp`)

Language-agnostic contract for the MCP (Model Context Protocol) surface, frozen
ahead of the Go rewrite (#210, #225). Source of truth in the Node backend:
[`src/mcp/tools/`](../../src/mcp/tools/) and
[`src/mcp/notifications.ts`](../../src/mcp/notifications.ts).

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
  data?: { label?; host?; port?; username?; description?: string|null } }
```

Per-action success payload (JSON in the text block):

- `list` → `{ endpoints: [{ id, label, host, port, username, description }] }`
  _(note: no `userVerification`/`agentForward`/`isDemo` — narrower than REST)_
- `read` → the raw endpoint object
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

Debounced, per subscribed session:

- `notifications/shellwatch/output_available` — new output is buffered for a session.
- `notifications/shellwatch/session_status` — session status changed.

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
