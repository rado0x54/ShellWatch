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
| `terminal:closed`  | `sessionId`                                                                                   | Session closed. Any buffered output not yet delivered to this connection is flushed as a final `terminal:output` frame immediately **before** this message (no extra frame when the connection is already caught up), and within the same attachment no `terminal:output` follows it (a later re-attach to a retained ended session — kept 5 minutes, at most 10 per account — may legitimately fetch output again). _(Redundant with `terminal:status {status:"closed"}` — see inconsistencies.)_                                                                                                                                                                                               |
| `terminal:mode`    | `sessionId`, `mode`                                                                           | Control-mode change. `mode ∈ {control, observer}`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `terminal:file`    | `sessionId`, `transferId`, `direction`, `path`, `bytes`, `status`, `tier`, `mcpClientName`, … | An MCP agent moved (or is moving) a file through this session (#263). Sent to connections **attached** to the session: on create, on progress (debounced ~250 ms) and on every terminal state. See [`terminal:file`](#terminalfile-263).                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `sessions:changed` | `sessions: SessionListEntry[]`                                                                | Full session-list snapshot for the account. Broadcast on any lifecycle change, and when a session is registered: a session still connecting (e.g. waiting for its SSH signature to be approved) is listed with `status: "opening"` (#273).                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `tickets:changed`  | —                                                                                             | A one-time access ticket of the account or its guest session changed state (minted, redeemed, attached/detached, attempt failed, admitted, ended, revoked, expired) (#306). Carries no data: refetch `GET /api/tickets`. Sent to the account's connections only.                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `error`            | `message: string`                                                                             | Non-fatal error (bad attach, input without control, etc.). No `code`, no `sessionId`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `notification:new` | `notification: Notification`                                                                  | A new entry in the account's notification log (#252): a server-originated event the user must not miss, e.g. a host-key mismatch (#241) — no pending action exists for those, so this message plus Web Push is how the account is told. The same `Notification` object (OpenAPI schema) is persisted and readable at `GET /api/audit/notifications` (the Notifications tab under Audit), so a reconnecting client catches up from the log; toasts dedupe by `notification.id` against the HTTP error that may carry the same id (`Error.notificationId`). Client behavior derives from `type` + `payload`, never from title/detail text; unknown types render title/detail with no typed action. |

### `SessionListEntry`

```ts
{
  sessionId: string;
  endpointId: string;
  status: TerminalStatus; // opening | open | closing | closed | error
  createdAt: string; // ISO-8601
  source: string; // "ui" | "mcp" | "ssh" | "ticket" — typed as bare string on the wire
  mode: "control" | "observer"; // this connection's mode for the session
  // Source "ticket" only (#306), omitted otherwise:
  ticketId?: string;
  ticketLabel?: string; // may be ""
  guestAttached?: boolean; // the guest's browser holds a /ws/guest connection
}
```

A guest session (source `ticket`) attaches as **observer** for the owner, like
`mcp`/`ssh`; the owner can take control, type and close it. Guest input does
not depend on the owner's control mode. A `sessions:changed` is also sent when
the guest attaches or detaches, so `guestAttached` stays current.

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

- `unauthenticated-endpoint` (#311) — a connection was **refused** because
  the server accepted SSH `none` authentication: the handshake completed
  without any key being asked for, so no human approved it. ShellWatch closes
  the connection before opening any channel; there is no action to resolve
  and no way to allow such an endpoint. Severity `error`. Replaces
  `session-connect-failed` for this case (exactly one notification per
  refusal). Payload:

  ```ts
  {
    endpointId: string;
    endpointLabel: string;
    endpointAddress: string; // user@host:port
    remoteUser: string; // the SSH user the server let in
    trigger: string; // "ui" | "mcp" | "ssh"
    mcpClientName: string; // "" outside MCP
    sourceIp: string;
    auditId: string; // the unauthenticated-endpoint row in /api/audit/signings ("" if the audit write failed)
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
  upload (`status` may be `completed` or `cancelled`) whose staging cleanup a
  restart cut short; severity `warning`. Payload:

  ```ts
  {
    transferId: string;
    sessionId: string;
    endpointId: string;
    direction: string; // "upload" | "download"
    path: string;
    status: string; // "failed" | "expired"; "completed" | "cancelled" only from startup reconciliation (cleanup "failed")
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

### Endpoint-auth trigger `ticket` (#306)

An endpoint-auth sign request raised while admitting a ticket guest carries
`context.trigger.kind: "ticket"` (`GET /api/actions/:id`). There is no new
approval type: approving the normal `webauthn-sign` / `key-approve` prompt is
what admits the guest; Skip (deny) moves on to the next key.

```ts
trigger: {
  kind: "ticket";
  sourceIp: string;          // the guest's address (resolved under server.trustProxy)
  reason?: string;           // SELF-REPORTED by the guest; omitted when empty
  ticketId: string;          // DELETE /api/tickets/{ticketId} revokes it ("Revoke ticket")
  ticketLabel: string;       // may be ""
  channel: "web";            // "ssh" follows with #307
  userAgent?: string;        // SELF-REPORTED by the guest browser
  confirmationCode: string;  // also on the guest's waiting screen
  agentForward: boolean;     // the ticket's option
  lifetimeSeconds: number;   // the ticket's option
}
```

The signing audit row records the reason in its `mcpReason` column (the
generic trigger reason).

The `sign:request` toast payload for such an action carries an extra `ticket`
object. When it is present, the SPA's toast names the guest request and shows
the code, but offers no Approve/Sign: the owner approves on `/sign/:id` after
comparing the code (Skip stays available in the toast). Ordinary prompts
carry no `ticket` key.

```ts
ticket?: {
  ticketId: string;
  ticketLabel: string;       // may be ""
  confirmationCode: string;
  reason?: string;           // SELF-REPORTED by the guest; omitted when empty
  sourceIp?: string;         // the guest's address
}
```

The Web Push notification for it reads "Guest Access Requested" and carries
neither the code nor the reason.

# Guest WebSocket (`/ws/guest`, #306)

The connection a one-time access guest's browser holds while it waits for
admission and then uses as its terminal. It is a separate endpoint with its
own registry: a guest connection is never in the account hub's connection set,
so `sessions:changed`, `sign:request`, `notification:new`, `tickets:changed`
and other sessions' output can never reach it.

## Transport & auth

- Endpoint: `GET /ws/guest` (HTTP upgrade). Gate-exempt: **no bearer** is read
  (a present, valid or invalid `Authorization` changes nothing), and no
  subprotocol is negotiated.
- Credential: the `__Host-sw_guest` cookie set by `POST /api/tickets/redeem`
  (`Secure; HttpOnly; SameSite=Strict; Path=/`, no `Domain`). It is valid only
  here, maps to one guest session, and is deleted server-side when the guest
  session closes, whatever the browser still holds.
- **Origin check** (cross-site WebSocket hijacking): the upgrade is accepted
  only when `Origin` exactly equals `server.externalUrl`'s origin (scheme, host
  and port; lowercased; the scheme's default port dropped on both sides).
  Missing, `null` or any other origin — a sibling subdomain included — answers
  **403** before the upgrade (log: `ws: guest origin rejected`). The expected
  origin never comes from `Host` or the connection's scheme, so a reverse proxy
  that rewrites `Host` or terminates TLS changes nothing.
- No live guest session for the cookie → **404** before the upgrade. Also
  behind `security.allowedNetworks` (403) and a per-IP rate limit (429).
- Several tabs of the redeeming browser may attach at once (each gets the
  catch-up, then the same output; input from any goes to the session); at most
  8 connections per guest session. A further one receives a final `closed`
  status and is closed.
- Inbound frames are capped at 1 MiB. The connection **is** the attachment:
  there are no attach/detach messages.

## Client → Server

| `type`   | Fields                         | Effect                                                                                                                                                                                             |
| -------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `input`  | `data: string`                 | Input to the admitted session. Dropped before admission.                                                                                                                                           |
| `resize` | `cols: number`, `rows: number` | Resize the admitted session's PTY. Dropped before admission.                                                                                                                                       |
| `end`    | —                              | End the guest session now (end reason `client.guest`), from any tab; closes every connection.                                                                                                      |
| `retry`  | —                              | Ask again: start a fresh admission attempt. Accepted only in `refused`, inside the admission window, from `retryAt` on, while attempts remain; otherwise ignored (the current `status` is resent). |

Every other frame (any `terminal:*` type included) is silently dropped.

## Server → Client

| `type`   | Fields                                           | Meaning                                                                                                                                 |
| -------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `status` | `state`, plus the fields below                   | The guest session's state. Sent on every transition and to each connection when it attaches.                                            |
| `output` | `data: string`, `offset: number`, `reset?: true` | Terminal output of the admitted session. On (re)attach after admission the whole buffer is sent once with `reset: true`; deltas follow. |

Every `status` frame carries `serverTime` (ISO 8601, the server's clock when
the frame was built). The guest device's clock may be off, so the page counts
`admissionDeadline` / `lifetimeDeadline` down against the offset between
`serverTime` and its own clock, not against local time alone.

`status` fields by `state` — none ever names the endpoint (label, address,
user) or carries a server error text; `message` is one of a few fixed texts:

| `state`   | Fields                                                                                                           | Meaning                                                                                                                                                                                                                                                                                                         |
| --------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pending` | `code`, `admissionDeadline?`                                                                                     | Waiting for the owner's approval. `code` is the confirmation code also shown on the approval prompt.                                                                                                                                                                                                            |
| `refused` | `code`, `admissionDeadline`, `remainingSeconds`, `retryAt`, `attemptsLeft`, `message: "Access was not granted."` | The attempt ended without admission (every key skipped or expired, or the connect failed). The guest may send `retry` from `retryAt` (15 s after the refusal) until the deadline. A guest session has at most 3 attempts; when the last one is refused it closes instead (`closed`, "Access was not granted."). |
| `open`    | `lifetimeDeadline`                                                                                               | Admitted; `output` frames follow.                                                                                                                                                                                                                                                                               |
| `closed`  | `message: "Access was not granted."` (never admitted) or `"The session has ended."`                              | Final. The server closes the connection after it.                                                                                                                                                                                                                                                               |

## Lifecycle bounds

| Bound            | Covers                                   | Value                    |
| ---------------- | ---------------------------------------- | ------------------------ |
| Redeem TTL       | minted → redeemed                        | per ticket, 1 min – 24 h |
| Attach window    | redeemed → first `/ws/guest` attach      | 30 s                     |
| Admission window | first attach → open, across all attempts | 5 min                    |
| Session lifetime | starts at admission                      | per ticket, 1 min – 8 h  |
| Reconnect grace  | after the last guest connection closes   | 60 s                     |

The first attempt starts on the first attach, so the owner is never prompted
for a guest that cannot see the code. A disconnect (reload, lost network) is
not an end: within the reconnect grace a new connection with the cookie
reattaches and catches up. End reasons (also the terminal session's close
reason where one exists): `client.guest`, `guest-disconnected`,
`ticket-lifetime`, `ticket-not-admitted`, `ticket-unattached`,
`ticket-revoked`, `endpoint-removed`, `account-deleted`, `shutdown`, or the
terminal session's own close reason after admission (`client.ui`,
`idle-timeout`, `server-hangup`, …).

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
