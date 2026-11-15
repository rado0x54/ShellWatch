<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# ShellWatch WebSocket protocol (`/ws`)

Language-agnostic contract for the browser ↔ server terminal WebSocket, frozen
ahead of the Go rewrite (#210, #225). Source of truth in the Node backend:
[`internal/ws/`](../../internal/ws/) (message shapes and the router)
(routing + control semantics).

## Transport & auth

- Endpoint: `GET /ws` (HTTP upgrade).
- Auth scope: `ui`. Browsers can't set an `Authorization` header on a WS
  handshake, so the token is passed as the **second** subprotocol:
  `Sec-WebSocket-Protocol: shellwatch.bearer, <token>`. The server negotiates
  the sentinel `shellwatch.bearer` back (never the token). Non-browser clients
  that already send `Authorization: Bearer` offer no subprotocol.
- Every frame is a JSON object with a `type` discriminator. Unparseable frames
  (`parseClientMessage` returns `null`) are **rejected with a reply**:
  `{ type: "error", message: "Invalid message format" }` (`ws-handler.ts`) — the
  connection stays open. Handler exceptions similarly reply with `error`.
- Inbound size: one client→server message is capped at **1 MiB**. A larger
  frame closes the connection with **1009** (message too big); outbound
  server→client frames are not capped.
- All messages carry `sessionId` **except** the server→client `sessions:changed`
  and `error`.

## Control vs. observer model

Each WS connection tracks two per-session sets: **attached** and **controlled**.

- `terminal:attach` is ownership-gated (session must belong to the caller's
  account). On attach, **UI-sourced** sessions (`source === "ui"`) are auto-put
  into control mode; `mcp`/`ssh` sessions attach as **observer**.
- `terminal:input` and `terminal:resize` require both _attached_ and _control_.
  Input on a session you don't control returns an `error`; resize is silently
  dropped (fires on every layout change — see the [asymmetry](#asymmetry-notes)).
- Multiple connections may observe one session; control is per-connection state,
  not a global lock. (See known issue #150: the UI "Release" button is shown for
  UI sessions where release is a no-op for meaningful purposes.)

## Client → Server

| `type`                     | Fields                                      | Effect                                                                                                                                                                                                                                                                                                           |
| -------------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `terminal:attach`          | `sessionId`, `afterOffset?: number`         | Subscribe. Replies with `terminal:status`, `terminal:mode`, and buffered `terminal:output` (delta from `afterOffset`, or full buffer with `reset:true` if the offset was evicted). One `terminal:file` frame per unfinished file transfer of the session follows (#263). Ownership-gated → `error` if not owned. |
| `terminal:detach`          | `sessionId`                                 | Unsubscribe; clears attached + controlled. Silent.                                                                                                                                                                                                                                                               |
| `terminal:input`           | `sessionId`, `data: string`                 | Send input to the shell. Requires attached + control, else `error`.                                                                                                                                                                                                                                              |
| `terminal:resize`          | `sessionId`, `cols: number`, `rows: number` | Resize PTY. Requires attached + control, else **silently** ignored.                                                                                                                                                                                                                                              |
| `terminal:close`           | `sessionId`                                 | Close the session (reason `client.ws`). Ownership-gated → `error`.                                                                                                                                                                                                                                               |
| `terminal:take-control`    | `sessionId`                                 | Enter control mode; replies `terminal:mode {mode:"control"}`. Ownership-gated → `error`.                                                                                                                                                                                                                         |
| `terminal:release-control` | `sessionId`                                 | Leave control mode; replies `terminal:mode {mode:"observer"}`. **Silent** if not attached.                                                                                                                                                                                                                       |

## Server → Client

| `type`             | Fields                                                                                        | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------ | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `terminal:output`  | `sessionId`, `data: string`, `offset: number`, `reset?: true`                                 | Output chunk. `offset` is the absolute buffer offset after this chunk. `reset:true` means the client must clear its buffer first (offset was evicted).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `terminal:status`  | `sessionId`, `status`                                                                         | The session's status, sent **once** in the `terminal:attach` reply (the only emitter, `ws-message-router.ts`). It is **not** pushed on subsequent transitions — runtime status changes propagate via `sessions:changed`. `status ∈ {opening, open, closing, closed, error}`.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `terminal:closed`  | `sessionId`                                                                                   | Session closed. Any buffered output not yet delivered to this connection is flushed as a final `terminal:output` frame immediately **before** this message (no extra frame when the connection is already caught up), and within the same attachment no `terminal:output` follows it (a later re-attach to a retained post-mortem session may legitimately fetch output again). _(Redundant with `terminal:status {status:"closed"}` — see inconsistencies.)_                                                                                                                                                                                                                                    |
| `terminal:mode`    | `sessionId`, `mode`                                                                           | Control-mode change. `mode ∈ {control, observer}`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `terminal:file`    | `sessionId`, `transferId`, `direction`, `path`, `bytes`, `status`, `tier`, `mcpClientName`, … | An MCP agent moved (or is moving) a file through this session (#263). Sent to connections **attached** to the session: on create, on progress (debounced ~250 ms) and on every terminal state. See [`terminal:file`](#terminalfile-263).                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `sessions:changed` | `sessions: SessionListEntry[]`                                                                | Full session-list snapshot for the account. Broadcast on any lifecycle change, and when a session is registered: a session still connecting (e.g. waiting for its SSH signature to be approved) is listed with `status: "opening"` (#273).                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `error`            | `message: string`                                                                             | Non-fatal error (bad attach, input without control, etc.). No `code`, no `sessionId`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `notification:new` | `notification: Notification`                                                                  | A new entry in the account's notification log (#252): a server-originated event the user must not miss, e.g. a host-key mismatch (#241) — no pending action exists for those, so this message plus Web Push is how the account is told. The same `Notification` object (OpenAPI schema) is persisted and readable at `GET /api/audit/notifications` (the Notifications tab under Audit), so a reconnecting client catches up from the log; toasts dedupe by `notification.id` against the HTTP error that may carry the same id (`Error.notificationId`). Client behavior derives from `type` + `payload`, never from title/detail text; unknown types render title/detail with no typed action. |

### `SessionListEntry`

```ts
{
  sessionId: string;
  endpointId: string;
  status: TerminalStatus; // opening | open | closing | closed | error
  createdAt: string; // ISO-8601
  source: string; // "ui" | "mcp" | "ssh" — typed as bare string on the wire
  mode: "control" | "observer"; // this connection's mode for the session
}
```

### `terminal:file` (#263)

File activity of an MCP agent on a session, pushed to every connection attached
to it. Nobody is prompted — the file tools need no approval — but everyone
watching sees it.

```ts
{
  type: "terminal:file";
  sessionId: string;
  transferId: string; // same id as the tool result and the audit row
  tier: "inline" | "link"; // inline: one tool call; link: out-of-band HTTP transfer
  direction: "upload" | "download" | "list"; // upload = written to the host; "list" is inline only
  path: string; // absolute remote path
  status: "pending" | "active" | "completed" | "failed" | "cancelled" | "expired";
  bytes: number; // bytes moved so far
  totalBytes?: number; // expected size, when known
  sha256?: string; // of the bytes written / sent, once known
  error?: string;
  truncated?: boolean; // download: the file was observed to grow after the copy
  commitOutcome?: "ok" | "failed" | "unknown"; // link uploads
  cleanup?: "ok" | "failed"; // link uploads: staging cleanup
  stagingPath?: string; // staging directory while it exists; with cleanup "failed": the leftover
  mcpClientName: string; // client-reported name, or the OAuth client_id
}
```

- **Inline** operations (`shellwatch_list_dir` / `_read_file` / `_write_file`)
  produce exactly one frame, already terminal (`completed` or `failed`).
- **Link** transfers (`shellwatch_transfer_file`) produce `pending` when the
  link is minted, `active` once claimed, progress frames while bytes move, and a
  terminal frame. A further frame follows a terminal one when the staging
  cleanup settles (`cleanup`, and `stagingPath` cleared or left as the leftover).
  The audit row's internal `committing` state is reported as `active` here.
- **Reconnect:** the `terminal:attach` reply includes one frame per `pending` /
  `active` link transfer of the session, after `terminal:mode` and the buffered
  `terminal:output`. Finished transfers are not replayed; read them from
  `GET /api/audit/file-transfers?sessionId=…`.
- Frames are only sent to attached connections. A user who is not attached
  learns about a `failed` or `expired` link transfer through `notification:new`
  (`file-transfer-failed`).

### `notification:new` (#252)

```ts
{
  type: "notification:new";
  notification: {
    id: string;
    accountId: string;
    type: string; // e.g. "host-key-mismatch"; payload is typed per kind
    severity: "info" | "warning" | "error";
    title: string; // toast-sized headline
    detail: string | null; // long-form preformatted text ("Details" view)
    payload: object | null; // type-specific structured data
    createdAt: string; // ISO-8601
  }
}
```

Known `type` values and their `payload` shapes (clients ignore unknown types
gracefully — render title/detail, no typed action):

- `host-key-mismatch` (#241) — a dial aborted **before authentication**
  because the server presented a host key that differs from the pinned one;
  recovery is the endpoint settings page. Payload:

  ```ts
  {
    endpointId: string;
    endpointLabel: string;
    endpointAddress: string; // user@host:port
    keyType: string; // the key the server presented, e.g. "ssh-ed25519"
    observedFingerprint: string; // SHA256:...
    pinnedFingerprint: string; // SHA256:...
    auditId: string; // the host-key-mismatch row in /api/audit/signings
  }
  ```

- `session-connect-failed` — any other failed SSH connect, whatever the
  trigger (UI click or MCP agent); severity `warning`. Payload:

  ```ts
  {
    endpointId: string;
    endpointLabel: string;
    endpointAddress: string; // user@host:port
    trigger: string; // "ui" | "mcp" | "ssh"
    mcpClientName: string; // "" outside MCP
    mcpClientVersion: string;
    mcpReason: string;
    sourceIp: string;
    error: string; // the full error chain the requester also received
  }
  ```

- `file-transfer-failed` (#263) — an out-of-band file transfer ended `failed`
  or `expired`, including one interrupted by a server restart, or a finished
  upload (`status` may be `completed`) whose staging cleanup a restart cut
  short; severity `warning`. Payload:

  ```ts
  {
    transferId: string;
    sessionId: string;
    endpointId: string;
    direction: string; // "upload" | "download"
    path: string;
    status: string; // "failed" | "expired"
    error: string;
    bytes: number;
    commitOutcome: string; // "" | "ok" | "failed" | "unknown"
    cleanup: string; // "" | "ok" | "failed"
    stagingPath: string; // leftover staging directory when cleanup is "failed"
    mcpClientName: string;
  }
  ```

### Sign-request toasts and host keys (#241)

The `sign:request` server→client toast payload (sent by the approval layer on
the same socket) carries an optional `hostKey` object for endpoint-auth
actions, mirroring `SignRequestContext.hostKey` on `GET /api/actions/:id`:

```ts
hostKey?: {
  type: string;        // e.g. "ssh-ed25519"
  fingerprint: string; // SHA256:...
  status: "new" | "known"; // "new": approving this action ALSO pins the key
}
```

## Asymmetry notes

Deliberate, but worth preserving explicitly in the Go port:

- **Input** errors loudly (deliberate user action → feedback); **resize** and
  **release-control** fail **silently** when not attached/controlled (they fire
  on layout churn / teardown and would spam the client).
- `mode` in `SessionListEntry` (from `sessions:changed`, built globally) reflects
  the **broadcasting connection's** controlled-set, computed in
  `buildSessionList`. A connection observing someone else's control still sees
  its own `mode`.

## Parity checklist for the Go rewrite

- [ ] Subprotocol negotiation returns the sentinel, never the token.
- [ ] `terminal:attach` replays buffered output with correct `offset`/`reset`.
- [ ] UI-source auto-control vs. mcp/ssh observer-on-attach.
- [ ] Silent vs. erroring paths preserved exactly (input loud; resize/release silent).
- [ ] `terminal:closed` still emitted alongside `terminal:status` (or consciously dropped — see #225 normalization decision).
