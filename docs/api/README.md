<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# ShellWatch wire contract

Language-agnostic definition of every external interface ShellWatch exposes,
frozen ahead of the Go backend rewrite ([#210]) as the parity oracle described
in [#225]. The Go server must reproduce these exactly; when a shape is wrong or
confusing, change it here **and** in code as a deliberate, tested decision — not
by drift.

| Surface     | Artifact                                           | Source of truth                                              |
| ----------- | -------------------------------------------------- | ------------------------------------------------------------ |
| REST / HTTP | [`openapi.yaml`](./openapi.yaml)                   | `src/server/routes/`, `src/webauthn/`, `src/hydra/routes.ts` |
| WebSocket   | [`websocket-protocol.md`](./websocket-protocol.md) | `src/server/ws-protocol.ts`, `ws-message-router.ts`          |
| MCP tools   | [`mcp-tools.md`](./mcp-tools.md)                   | `src/mcp/tools/`, `src/mcp/notifications.ts`                 |

Coverage: every REST route is in `openapi.yaml`, including the anonymous
bootstrap surface (`/api/auth/passkey-status`, `/api/auth/register/options`,
`/api/auth/register`). Deliberately **not** schema-documented here:

- `/ws` and `/mcp` — non-REST protocols, in the companion docs above.
- `/agent-proxy` WebSocket framing (the Go agent-client bridge) — tracked
  separately; add when that surface stabilizes.
- The Hydra provider **GET** pages (`/api/hydra/{login,consent,logout,error}`)
  are HTML/redirect flows; the `hydra-provider` tag documents the JSON
  options/verify endpoints and points to `src/hydra/routes.ts` for the pages.

## Auth model (all surfaces)

One gate ([`src/server/auth/bearer-gate.ts`](../../src/server/auth/bearer-gate.ts)):
every protected request presents a Hydra opaque access token, validated by
introspection. `sub` → account id; authorization is **by scope only** (audience
is intentionally not checked):

- `/api/*` and `/ws` → scope `ui`
- `/mcp` → scope `mcp` (+ IP allowlist)
- `/agent-proxy` → scope `agent`

`/ws` takes the token via `Sec-WebSocket-Protocol: shellwatch.bearer, <token>`.
Exempt (no token): `/health`, `/api/version`, `/config.js`, `/manifest.json`,
`/api/auth/register(/options)`, `/api/auth/passkey-status`, and prefixes
`/api/hydra/`, `/api/passkey-invite/`, `/passkey-invite/`, `/.well-known/`,
`/_app/`.

## Regenerating / validating

The spec is **hand-authored** (Fastify routes carry no JSON schema today). To
serve it live or generate clients, the cheapest path is to attach
`@fastify/swagger` schemas to routes and diff the emitted document against this
file — that also tightens request validation (see #225 item 1). Until then,
treat this directory as the reviewed contract.

---

## Known inconsistencies (found while freezing the contract)

Catalogued so the Go rewrite can consciously **converge or preserve** each —
none are bugs today, but several will surprise a fresh client implementer.
Ordered roughly by how much they'd bite.

### A. Mutation response envelopes are not uniform

Across write endpoints the success body varies with no pattern a client can rely on:

| Endpoint                             | Success body                                     |
| ------------------------------------ | ------------------------------------------------ |
| `POST /api/endpoints`                | `{ status: "created", id }`                      |
| `PUT /api/endpoints/:id`             | `{ status: "updated" }`                          |
| `POST /api/sessions`                 | **bare `TerminalSession`** (no envelope)         |
| `DELETE /api/sessions/:id`           | `{ status: "closed" }`                           |
| `DELETE /api/push/subscribe`         | `{ ok: true }`                                   |
| `POST /api/push/subscribe`           | `{ id }`                                         |
| `POST /api/auth/sessions/revoke-all` | `{ status: "revoked_all" }`                      |
| `POST …/credentials/:id/confirm`     | `{ status: "active" }`                           |
| `POST …/credentials/:id/revoke`      | `{ status: "revoked", sessionsInvalidated }`     |
| `POST /api/passkey-invite/register`  | `{ status: "registered", label, fingerprint }`   |
| `POST /api/webauthn/register`        | `{ verified: true, credentialId, id, label, … }` |

`{ status: "<verb-past-tense>" }`, `{ ok }`, bare objects, and ad-hoc keys all
coexist. **Recommendation:** pick one convention (a `{ status }` string plus
resource fields) for the Go port; it's a natural cut point.

### B. `POST /api/sessions` returns a bare object; siblings return `{ status }`

Specific instance of (A) worth calling out: session-create returns the raw
`TerminalSession`, but endpoint-create returns `{ status, id }`. A generic
"create" client helper can't treat them the same.

### C. REST vs. MCP endpoint-create disagree on `id` ownership

- REST `POST /api/endpoints`: **server** generates a UUID, returns it.
- MCP `shellwatch_manage_endpoints` create: **caller** must supply `id`.

Same logical operation, opposite id semantics. Also, MCP `list` omits
`userVerification`, `agentForward`, and `isDemo` that REST returns. Two clients
build different mental models of "an endpoint."

### D. Near-identical WS message names differ by one character / tense

`terminal:close` (client→server, _do close_) vs. `terminal:closed`
(server→client, _did close_) vs. `terminal:detach` vs. `terminal:release-control`.
And `terminal:closed` is **redundant** with `terminal:status {status:"closed"}` —
two messages for one event. Easy to mis-wire. Consider dropping `terminal:closed`
or renaming the client verb (e.g. `terminal:request-close`).

### E. Two different "end of buffer" signals for the same ring buffer

WS `terminal:output` uses `reset?: true` (offset evicted → clear & replay);
MCP `shellwatch_read_output` returns `hasMore: boolean`; REST `/tail` returns
neither (just `data`). Same buffer, three different pagination/eviction
vocabularies.

### F. Errors are _mostly_ `{ error }` with no machine-readable `code` — with two exceptions

The general envelope is `{ error: "<human string>" }`, discriminated only by
HTTP status. Clients must string-match to distinguish, e.g., "already revoked"
(400) from "last active passkey" (400) — same status, different meaning. A stable
`code` across all routes would make the contract testable and i18n-friendly.

Two routes already break the pattern, in different directions:

- The **step-up gate** (401 on the five `requireStepUp` routes) _does_ return a
  `code`: `{ error, code }` with `code ∈ {stepup_required, stepup_expired,
stepup_wrong_action, stepup_wrong_account}` (`stepup-gate.ts`). This is the
  only machine-readable error code in the API today.
- The **Hydra/DCR** routes use `{ error, error_description }` OAuth-style — a
  third error shape.

So a Go port inherits three error envelopes; converging on one `{ error, code }`
is the natural cleanup.

### G. `409` vs `400` for "already revoked" is inconsistent across resources

`POST …/credentials/:id/revoke` returns **400** for "already revoked"; the
label route returns **409** for a duplicate label; `POST /api/actions/:id/deny`
returns **409** for "already resolved". "Conflicting-with-current-state" maps to
both 400 and 409 depending on the file. Pick one (409 is the conventional
choice) for state-conflict errors.

### H. `SessionListEntry.source` is typed as bare `string`

On the wire (`sessions:changed`) `source` is `string`, though the domain type is
`TerminalSource = "ui" | "mcp" | "ssh"`. The Go DTO should use the enum.

### I. Redundant discovery documents

`/.well-known/oauth-protected-resource` and
`/.well-known/oauth-protected-resource/mcp` return the **same** MCP metadata
(the first is a convenience alias). Harmless, but document it so the Go port
doesn't "discover" a bug and delete one.

### J. `PATCH` appears exactly once

Only `…/credentials/:id/label` uses `PATCH`; every other partial update
(`PUT /api/endpoints/:id`, `PUT /api/auth/me`) uses `PUT`. Minor, but a client's
method-selection logic has to special-case it.

[#210]: https://github.com/rado0x54/ShellWatch/issues/210
[#225]: https://github.com/rado0x54/ShellWatch/issues/225
