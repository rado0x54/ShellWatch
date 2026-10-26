<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# ShellWatch MCP tools (`/mcp`)

Language-agnostic contract for the MCP (Model Context Protocol) surface.
Implementation: [`internal/mcp/`](../../internal/mcp/) (`server.go`,
`tools_sessions.go`, `tools_endpoints.go`, `resources.go`).

## Transport & auth

The server is a **stateless dual-era** MCP streamable-HTTP server (#243):

- Endpoint: `POST /mcp` only. `GET` and `DELETE` answer **405** (`Allow: POST`).
- Protocol revisions served: **`2026-07-28`**, **`2025-11-25`**, **`2025-06-18`**
  (`server/discover` lists them). `2025-03-26`/`2024-11-05` were dropped; a
  request with an unsupported `Mcp-Protocol-Version` header gets a plain **400**
  naming the supported list. A header-less legacy request is still answered by
  the legacy handshake rules (treated as the oldest handshake era).
- **No protocol-level sessions**: no `Mcp-Session-Id` is minted or honoured.
  Terminal sessions (`sessionId` tool arguments) are the durable, server-minted
  handles. The legacy `initialize` handshake is answered (with the live
  instructions), but every POST is an independent request.
- **`2026-07-28` clients** carry `_meta` per request
  (`io.modelcontextprotocol/protocolVersion`, `clientCapabilities`, optional
  `clientInfo`) plus the required `Mcp-Method`/`Mcp-Name` headers (errors
  `-32020` HeaderMismatch / `-32022` UnsupportedProtocolVersion). `server/discover`
  replaces `initialize` and also returns the instructions.
- Auth scope: `mcp` via `Authorization: Bearer <token>`. Additionally fronted by
  the IP allowlist (`config.security.allowedNetworks`). The 401 challenge
  advertises `resource_metadata` (RFC 9728) and `scope="mcp"`.
- **Ownership is `(account, OAuth client_id)`** — the `client_id` from token
  introspection. A terminal session created over MCP belongs to that client:
  only requests authenticated for the same account **and** client can
  list/read/write/close it (anything else gets the uniform
  `session not found: <id>` tool error). Ownership survives reconnects and
  server restarts do not apply (sessions are live SSH connections). Sessions end
  by `shellwatch_close_session`, the remote side closing, the server-wide idle
  janitor (`sessions.idleTimeoutMinutes`), account deletion, or consent
  revocation of the owning client (Settings → Sessions; close reason
  `agent-disconnect`).
- **Agent attribution:** `mcpClientName`/`mcpClientVersion` (approval UI, audit)
  come from the request's `_meta` `clientInfo` when present (`2026-07-28`);
  otherwise they fall back to the OAuth `client_id`. A legacy client's
  `initialize`-advertised name cannot reach stateless tool calls and is ignored.
- Cache hints (SEP-2549): every cacheable result is `cacheScope: "private"`;
  `tools/list` carries `ttlMs: 3600000`, everything else `ttlMs: 0`.
- **All tool results are `content: [{ type: "text", text: <JSON string> }]`** —
  the payload is JSON _stringified inside a text block_, not a native structured
  result. Errors are `{ isError: true, content: [{ type:"text", text: <message> }] }`.
  (`resultType: "complete"` is appended by the protocol layer on `2026-07-28`.)

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

Input: `{ sessionId: string; afterOffset?: number; limit?: number /* default 4000 */;
waitMs?: number /* 0–30000, default 0 */ }`.
Success → `OutputReadResult`: `{ data: string, offset: number, hasMore: boolean }`.

`waitMs` long-polls (#243): when no output past `afterOffset` exists yet, the
call blocks until some arrives, the session reaches a terminal state, or
`waitMs` elapses — then reads once more and returns (possibly with empty
`data`). Values outside 0–30000 are an `isError` result.
_(Note: `hasMore` here vs. WS `terminal:output`'s `reset` flag — different
buffer-boundary signals for the same ring buffer.)_

### `shellwatch_close_session`

Input: `{ sessionId: string }`. Success → `{ status: "closed" }`.
(Close reason recorded as `client.mcp`.)

### `shellwatch_manage_keys`

Input: `{ action: "list" | "read"; id?: string }`.

- `list` → `{ keys: [{ id, label, type, fingerprint }] }`
- `read` → `{ id, label, type, fingerprint, publicKey }`

## Resources & server → client updates

> **Breaking (#243):** the custom `notifications/shellwatch/output_available`
> and `notifications/shellwatch/session_status` methods are **removed in every
> era** — the stateless transport has no standalone SSE stream to carry them,
> and `subscriptions/listen` types are a closed set. Replacements below.

Sessions are exposed as resources (account+client scoped, same ownership rules
as the tools; foreign/unknown ids are an indistinguishable resource-not-found):

- `shellwatch://sessions` — the owned-session list:
  `{ sessions: [{ sessionId, endpointId, status, createdAt, offset }] }`
- `shellwatch://sessions/{sessionId}` — one session document:
  `{ sessionId, endpointId, status, createdAt, offset }`
  (`offset` is the offset past the last buffered output byte)

A `2026-07-28` client opts in on `subscriptions/listen` with
`resourceSubscriptions` naming those URIs and receives
`notifications/resources/updated`:

- on new output for a session URI, **debounced** per session
  (`notifications.mcp.debounceMs`, default 100 ms);
- immediately on every status change, for the session URI **and** the list URI.

Subscriptions require protocol `>= 2026-07-28` (a legacy `resources/subscribe`
is rejected with a hint); they live exactly as long as the listen stream.

Pre-`2026-07-28` clients cannot receive server-initiated notifications on this
server at all — they **long-poll** instead: `shellwatch_read_output` with
`waitMs` (below) returns as soon as output arrives, which removes the need for
notification-driven polling in every era.

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
