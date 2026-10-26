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

| `type`                     | Fields                                      | Effect                                                                                                                                                                                                                     |
| -------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `terminal:attach`          | `sessionId`, `afterOffset?: number`         | Subscribe. Replies with `terminal:status`, `terminal:mode`, and buffered `terminal:output` (delta from `afterOffset`, or full buffer with `reset:true` if the offset was evicted). Ownership-gated → `error` if not owned. |
| `terminal:detach`          | `sessionId`                                 | Unsubscribe; clears attached + controlled. Silent.                                                                                                                                                                         |
| `terminal:input`           | `sessionId`, `data: string`                 | Send input to the shell. Requires attached + control, else `error`.                                                                                                                                                        |
| `terminal:resize`          | `sessionId`, `cols: number`, `rows: number` | Resize PTY. Requires attached + control, else **silently** ignored.                                                                                                                                                        |
| `terminal:close`           | `sessionId`                                 | Close the session (reason `client.ws`). Ownership-gated → `error`.                                                                                                                                                         |
| `terminal:take-control`    | `sessionId`                                 | Enter control mode; replies `terminal:mode {mode:"control"}`. Ownership-gated → `error`.                                                                                                                                   |
| `terminal:release-control` | `sessionId`                                 | Leave control mode; replies `terminal:mode {mode:"observer"}`. **Silent** if not attached.                                                                                                                                 |

## Server → Client

| `type`             | Fields                                                        | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------ | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `terminal:output`  | `sessionId`, `data: string`, `offset: number`, `reset?: true` | Output chunk. `offset` is the absolute buffer offset after this chunk. `reset:true` means the client must clear its buffer first (offset was evicted).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `terminal:status`  | `sessionId`, `status`                                         | The session's status, sent **once** in the `terminal:attach` reply (the only emitter, `ws-message-router.ts`). It is **not** pushed on subsequent transitions — runtime status changes propagate via `sessions:changed`. `status ∈ {opening, open, closing, closed, error}`.                                                                                                                                                                                                                                                                                                                                                                           |
| `terminal:closed`  | `sessionId`                                                   | Session closed. Any buffered output not yet delivered to this connection is flushed as a final `terminal:output` frame immediately **before** this message (no extra frame when the connection is already caught up), and within the same attachment no `terminal:output` follows it (a later re-attach to a retained post-mortem session may legitimately fetch output again). _(Redundant with `terminal:status {status:"closed"}` — see inconsistencies.)_                                                                                                                                                                                          |
| `terminal:mode`    | `sessionId`, `mode`                                           | Control-mode change. `mode ∈ {control, observer}`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `sessions:changed` | `sessions: SessionListEntry[]`                                | Full session-list snapshot for the account. Broadcast on any lifecycle change.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `error`            | `message: string`                                             | Non-fatal error (bad attach, input without control, etc.). No `code`, no `sessionId`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `notification:new` | `notification: Notification`                                  | A new entry in the account's notification log (#252): a server-originated event the user must not miss, e.g. a host-key mismatch (#241) — no pending action exists for those, so this message plus Web Push is how the account is told. The same `Notification` object (OpenAPI schema) is persisted and readable at `GET /api/notifications`, so a reconnecting client catches up from the log; toasts dedupe by `notification.id` against the HTTP error that may carry the same id (`Error.notificationId`). Client behavior derives from `type` + `payload`, never from title/detail text; unknown types render title/detail with no typed action. |

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
