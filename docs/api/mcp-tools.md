<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# ShellWatch MCP tools (`/mcp`)

Language-agnostic contract for the MCP (Model Context Protocol) surface.
Implementation: [`internal/mcp/`](../../internal/mcp/) (`server.go`,
`tools_sessions.go`, `tools_endpoints.go`, `tools_files.go`, `resources.go`);
the file tools are backed by [`internal/transfer/`](../../internal/transfer/).

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
- **Onboarding: CIMD is the recommended path; DCR is the deprecated fallback.**
  The `2026-07-28` authorization spec says clients and servers SHOULD support
  **Client ID Metadata Documents** (`draft-ietf-oauth-client-id-metadata-document-02`)
  and deprecates RFC 7591 DCR, keeping it only for backwards compatibility.
  ShellWatch serves both:
  - **CIMD** — the `client_id` **is** an `https` URL serving the client's own
    metadata. `/.well-known/oauth-authorization-server` advertises
    `client_id_metadata_document_supported: true` and points
    `authorization_endpoint` at `GET /api/hydra/authorize`, which resolves the
    document and provisions a Hydra client whose `client_id` is that URL. There
    is **no registration call at all** on this path. Requirements on the URL and
    the document (https only, a path component, no query or fragment, no
    `client_secret`, `token_endpoint_auth_method` ∈ {`none`, `private_key_jwt`},
    a 5 KB read cap, no redirects followed, and exact `redirect_uri` matching
    with the RFC 8252 §7.3 loopback-port exception) are in
    [`openapi.yaml`](./openapi.yaml) under `authorizeOauthClient`.
    The client's **registered scope comes from the document**, not from the
    authorization request: declare `"scope": "agent"` (or `"mcp agent"`) in the
    document if the client needs more than the default `mcp`, since a request
    may not exceed what the document registered.
  - **DCR** — `POST /api/hydra/register`, unchanged and still supported. Note
    that each call mints a **new** Hydra client, so repeated registrations of
    the same software accumulate rows; CIMD collapses them onto one identity
    keyed by the URL.

  Either way the same local policy applies — `hydra.dcr.redirectUriPatterns` and
  `hydra.dcr.allowedScopes` are shared, ShellWatch never issues a client secret,
  and every registration, refresh and rejection is recorded in the admin-only
  log at `GET /api/audit/oauth-clients` (Audit → OAuth Clients).

  One consequence of CIMD worth planning for: because the URL is the identity,
  **all installs of a client share one Hydra client row**, so revoking it under
  Settings → Authorized clients revokes every install for that account. With DCR
  each install was separately revocable.

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

## File tools (#263)

Four tools move files to and from the remote host of an **open** session. They
run over the **SFTP subsystem on the session's existing SSH connection** — no
new signature and no approval prompt; ownership is the session's
`(account, OAuth client_id)` and a foreign or unknown id gets the uniform
`session not found: <id>`. They do not widen what an agent can already do
through the terminal; they make it visible: every operation writes a
`file_transfers` audit row (`GET /api/audit/file-transfers`) and a
`terminal:file` WebSocket frame, all carrying the same `transferId`.

### Privilege and path semantics (all four tools)

Sharing the SSH connection does **not** share the shell. The SFTP subsystem
runs as the **SSH login user** with its own working directory: after
`cd /srv/app` or `sudo -i` in the terminal, the file tools still see the login
user's view.

- **Paths must be absolute.** A relative path is an `isError`:
  `path must be absolute; the file tools do not follow the shell's working
directory`.
- Writing a root-owned file needs the login user to have write permission;
  otherwise the call fails with the SFTP permission error and the agent must
  fall back to the terminal (`sudo tee`).
- **Symlinks:** reads follow them. Writes of either tier `lstat` the
  destination first and refuse a symlink (`destination is a symlink; write to
its target explicitly`). This check is **best effort under concurrent
  filesystem changes**: SFTP v3 has no `O_NOFOLLOW`, so a symlink inserted
  between the check and an in-place inline write is followed, and one inserted
  before an `overwrite: true` link commit is replaced by the regular file. Only
  the `overwrite: false` link commit is immune (`link(2)` fails on any existing
  entry).
- **Special files:** directories, devices, FIFOs and sockets are refused as
  read sources and write destinations; `shellwatch_list_dir` reports them by
  `type`.
- **`mode`** (where accepted) is the permission bits, at most `0777` —
  setuid/setgid/sticky are refused. Pass an **octal string** (`"0644"`,
  `"600"`) or a JSON number holding the numeric value (`420` is `0o644`). A
  number is never read as octal digits, so `644` (= `0o1204`) is rejected
  rather than silently applied. Results report both `mode` (number) and
  `modeOctal` (string).
- A session whose transport has no file capability answers
  `this session's transport does not support file transfer`; a host without an
  SFTP subsystem answers the SSH error. There is no `exec cat` fallback.

### Inline tier — small text/config files

Bounded by `transfer.maxInlineBytes` (default 256 KiB, decoded) per call. One
SFTP channel per session, opened on first use and reused; at most
`transfer.maxInlineConcurrency` (default 2) calls run at once per session,
further ones wait. The whole call, channel setup included, is bounded by
`transfer.inlineTimeoutSeconds` (default 30): past it the result is the
`isError` `file operation timed out`. A timed-out write that had already opened
its destination says so (`…; the destination was already opened and may hold
partial content`) — whatever was written stays.

#### `shellwatch_list_dir`

Input: `{ sessionId: string; path: string; maxEntries?: number /* default 200, cap 1000 */ }`.
Success →

```ts
{ transferId: string;
  entries: [{ name; type: "file" | "directory" | "symlink" | "fifo" | "socket" | "device" | "other";
              size: number; mode: number; modeOctal: string; mtime: string /* ISO */;
              target?: string /* symlink only */ }];
  truncated: boolean }
```

Entries are sorted by name; `truncated` is `true` when more than `maxEntries`
exist.

#### `shellwatch_read_file`

Input: `{ sessionId: string; path: string; encoding?: "utf8" | "base64" }`.
Success → `{ transferId, path, size, mode, modeOctal, mtime, sha256, content, encoding }`.

The read is bounded, not the stat: content streams through a limit of
`maxInlineBytes + 1`, so a file above the limit — including one that grows past
it after the preliminary `stat` — fails with an `isError` naming the size and
pointing at `shellwatch_transfer_file`. **Partial content is never returned.**
`utf8` (default) refuses content that is not valid UTF-8 and asks for `base64`;
`base64` lets small binaries round-trip. `size`, `mode` and `mtime` come from
the open handle; `sha256` describes the returned bytes.

#### `shellwatch_write_file`

Input:

```ts
{ sessionId: string; path: string; content: string;
  encoding?: "utf8" | "base64";
  overwrite?: boolean /* default false */;
  mode?: number | string }
```

Success → `{ transferId, path, bytes, sha256 }`.

- `content` is decoded and size-checked **before the destination is opened**:
  malformed base64 or an oversized payload never touches an existing file.
- `overwrite: false` creates exclusively (`O_CREAT|O_EXCL`) and fails if the
  path exists. The mode (`mode`, else `0644`) is set on the still-empty file
  before any content byte is written.
- `overwrite: true` truncates **in place**, so inode, owner, mode and hard
  links survive; a supplied `mode` is applied after the write and deliberately
  overrides preservation. A path that does not exist yet is created as above.
- Residual window: a process that opened the just-created, still-empty file
  between create and chmod keeps its descriptor. For secrets use the link
  upload, which stages privately.

### Link tier — `shellwatch_transfer_file`

For large or binary files. The bytes never pass through the model: `create`
mints a short-lived, single-use URL plus an exact `curl` command, the host's
shell or sandbox runs it, and `status` reports the outcome (`curl`'s output
never reaches the server).

```ts
{ action: "create"; sessionId: string; direction: "upload" | "download"; path: string;
  maxBytes?: number /* default and cap: transfer.maxTransferBytes */;
  sha256?: string /* upload: expected hex digest */;
  overwrite?: boolean /* upload, default false */;
  mode?: number | string /* upload */ }
  → { transferId, url, method: "PUT" | "GET", expiresAt, maxBytes,
      command: "curl -fsS -T './backup.tgz' 'https://<server>/api/transfers/<token>'" }

{ action: "status" | "cancel"; transferId: string }
  → { transferId, status: "pending" | "active" | "completed" | "failed" | "cancelled" | "expired",
      direction, path, bytes, totalBytes?, sha256?, error?, truncated?: boolean,
      commitOutcome?: "ok" | "failed" | "unknown",
      cleanup?: "ok" | "failed", stagingPath? }
```

An unknown or foreign `transferId` answers `transfer not found: <id>`. `status`
answers from memory while the record is retained
(`transfer.statusRetentionSeconds`, `transfer.maxStatusRecords`) and from the
audit row afterwards.

**The link.** `PUT`/`GET /api/transfers/{token}` (see
[`openapi.yaml`](./openapi.yaml)). The token — 32 random bytes — is the only
credential on the route, because the sandbox running `curl` has no OAuth
token. It is bound to account, client, session, direction, path, byte cap and
expected digest; it is **single use** and must be claimed within
`transfer.linkTtlSeconds` (default 300). The route sits behind
`security.allowedNetworks` like `/mcp`: a sandbox that egresses from a
different IP than the MCP client (claude.ai code execution, for one) needs its
own CIDR — and its own egress allowlist must include the ShellWatch domain, or
`curl` gets a 403 from the sandbox's proxy before reaching ShellWatch. The
server never fetches from a URL the agent names.

**Remote-server contract for uploads.** Link uploads require an
OpenSSH-compatible `sftp-server` advertising **`posix-rename@openssh.com`** and
**`hardlink@openssh.com`**. Without them `create` is an `isError`
(`remote SFTP server lacks posix-rename/hardlink extensions; use
shellwatch_write_file or the PTY`). There is **no fallback to weaker
semantics**. The inline tools and downloads need only SFTP v3 core.

**Upload commit.**

1. A private staging directory `.<base>.<random>.tmp/` is created next to the
   destination and set to `0700` while still empty; only then is `data` created
   inside it (`O_CREAT|O_EXCL`) and set to `0600` before the first byte. A name
   collision is a hard failure — an existing entry is never reused.
2. The body streams under the byte cap with a running sha256. Overrun, digest
   mismatch, idle timeout, cancellation or session end stop it and run cleanup.
3. The final mode is set on the staged file: `mode` if given; else the existing
   file's permission bits when `overwrite: true` replaces a regular file; else
   `0644`.
4. Commit: `overwrite: false` → **hardlink** (atomic no-clobber: fails if
   _anything_ exists at the destination; a filesystem that refuses hard links
   fails the transfer without touching the destination). `overwrite: true` →
   **posix-rename** (atomic replace). The destination is never removed before
   the replacement is in place.
5. `completed` is reported **only after the commit was acknowledged**. A
   commit the server rejected is `failed` with `commitOutcome: "failed"`
   (destination untouched / original still in place). A connection lost after
   the commit was sent and before its reply arrived is `failed` with
   **`commitOutcome: "unknown"`** — inspect the destination (size, sha256)
   before retrying. The same applies when the server keeps the connection open
   but does not answer the commit within `transfer.commitTimeoutSeconds`
   (default 30): the transfer's channel is closed and the outcome is `unknown`.
   This is the only timeout that applies once the commit has been issued.
6. Cleanup of the staging directory is best effort and bounded
   (`transfer.cleanupTimeoutSeconds`). When it fails or cannot run (remote
   hangup, session torn down), the result carries `cleanup: "failed"` and the
   `stagingPath` of the leftover.
7. Both commits create a **new inode**: ownership, ACLs and hard links of a
   replaced file are not preserved (unlike `shellwatch_write_file`, which
   truncates in place).

**Download.** The file is opened first; size comes from the open handle and is
sent as `Content-Length`. A premature EOF observed before that many bytes were
read ends the response short (curl reports a partial transfer) and the status
is `failed` with `error: "file shrank during transfer"`. After the last byte
the server probes for one more on the same handle: data there sets
`truncated: true`, meaning growth was **observed** at that moment — concurrent
mutation cannot be detected in general. `sha256` always describes the bytes
actually sent. `completed` means the server finished writing the response; it
cannot attest that `curl` saved the file. Copying a live database file gives no
consistency guarantee.

**Lifecycle.**

- A claim checks the token, that the session is still `open`, and the active
  capacity (`transfer.maxActivePerAccount`, `transfer.maxActiveGlobal`) in one
  step, before any SFTP resource exists. A capacity shortage answers **503**
  with `Retry-After` and leaves the link `pending`, so `curl --retry` can still
  succeed within the TTL. `create` is bounded separately by
  `transfer.maxPendingPerSession` / `transfer.maxPendingGlobal` (an `isError`
  naming the limit).
- When the session leaves `open` — closed, idle-timed out, consent revoked,
  account deleted, remote hangup — its unused links become `cancelled` and its
  active transfers are aborted (`cancelled`; `failed` on a remote hangup).
- **Cancel vs commit:** a cancel that arrives before the commit call wins
  (`cancelled`, nothing at the destination). Once the commit has been issued a
  cancel is ignored and the outcome is whatever the commit reports. `cancel`
  returns promptly; cleanup settles in the background and shows up in a later
  `status`. Cancelling never touches the terminal.
- An active transfer fails after `transfer.idleTimeoutSeconds` without a byte
  moved, and after `transfer.maxDurationSeconds` in total.
- **Session idle timeout:** successful inline operations and real link-transfer
  progress count as session activity. Minting links, polling `status`, listing
  an empty directory and failed claims do not.
- Links and live transfers do not survive a server restart. Transfers that were
  unfinished read `failed` afterwards (`error: "server restarted"`;
  `commitOutcome: "unknown"` if the restart hit mid-commit), with the staging
  path preserved.
- A link transfer that ends `failed` or `expired` raises a
  `file-transfer-failed` notification for the account.

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
