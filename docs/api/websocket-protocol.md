<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# ShellWatch WebSocket protocol (`/ws`)

Language-agnostic contract for the browser ↔ server terminal WebSocket, frozen
ahead of the Go rewrite (#210, #225). Source of truth in the Node backend:
[`src/server/ws-protocol.ts`](../../src/server/ws-protocol.ts) (message shapes)
and [`src/server/ws-message-router.ts`](../../src/server/ws-message-router.ts)
(routing + control semantics).

## Transport & auth

- Endpoint: `GET /ws` (HTTP upgrade).
- Auth scope: `ui`. Browsers can't set an `Authorization` header on a WS
  handshake, so the token is passed as the **second** subprotocol:
  `Sec-WebSocket-Protocol: shellwatch.bearer, <token>`. The server negotiates
  the sentinel `shellwatch.bearer` back (never the token). Non-browser clients
  that already send `Authorization: Bearer` offer no subprotocol.
- Every frame is a JSON object with a `type` discriminator. Unparseable frames
  are dropped (`parseClientMessage` returns `null`).
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

| `type`             | Fields                                                        | Meaning                                                                                                                                                |
| ------------------ | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `terminal:output`  | `sessionId`, `data: string`, `offset: number`, `reset?: true` | Output chunk. `offset` is the absolute buffer offset after this chunk. `reset:true` means the client must clear its buffer first (offset was evicted). |
| `terminal:status`  | `sessionId`, `status`                                         | Status change. `status ∈ {opening, open, closing, closed, error}`.                                                                                     |
| `terminal:closed`  | `sessionId`                                                   | Session closed. _(Redundant with `terminal:status {status:"closed"}` — see inconsistencies.)_                                                          |
| `terminal:mode`    | `sessionId`, `mode`                                           | Control-mode change. `mode ∈ {control, observer}`.                                                                                                     |
| `sessions:changed` | `sessions: SessionListEntry[]`                                | Full session-list snapshot for the account. Broadcast on any lifecycle change.                                                                         |
| `error`            | `message: string`                                             | Non-fatal error (bad attach, input without control, etc.). No `code`, no `sessionId`.                                                                  |

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
