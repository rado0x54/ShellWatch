<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# ShellWatch wire contract

Language-agnostic definition of every external interface ShellWatch exposes,
frozen ahead of the Go backend rewrite ([#210]) as the parity oracle described
in [#225]. The Go server must reproduce these exactly; when a shape is wrong or
confusing, change it here **and** in code as a deliberate, tested decision — not
by drift.

| Surface     | Artifact                                               | Implementation                                                                                   |
| ----------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| REST / HTTP | [`openapi.yaml`](./openapi.yaml)                       | `internal/rest/`, `internal/webauthn/`, `internal/hydra/` (+ generated models in `internal/api`) |
| WebSocket   | [`websocket-protocol.md`](./websocket-protocol.md)     | `internal/ws/`                                                                                   |
| MCP tools   | [`mcp-tools.md`](./mcp-tools.md)                       | `internal/mcp/`                                                                                  |
| Agent proxy | [`agent-proxy-protocol.md`](./agent-proxy-protocol.md) | `internal/agentproxy/`, `agent-client/internal/proxy/`                                           |

Coverage: every REST route is in `openapi.yaml`, including the anonymous
bootstrap surface (`/api/auth/passkey-status`, `/api/auth/register/options`,
`/api/auth/register`). Deliberately **not** schema-documented here:

- `/ws`, `/mcp`, and `/agent-proxy` — non-REST protocols, in the companion
  docs above.
- The Hydra provider **GET** pages (`/api/hydra/{login,consent,logout,error}`)
  are HTML/redirect flows; the `hydra-provider` tag documents the JSON
  options/verify endpoints and points to `internal/hydra` for the pages.

## Auth model (all surfaces)

One gate ([`internal/auth/gate.go`](../../internal/auth/gate.go)):
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

## Conformance over the wire (e2e)

The black-box e2e suite in [`e2e/`](../../e2e) ([#244], [`docs/testing.md`](../testing.md))
is an additional conformance check of this contract: it runs the built server
against a real `sshd` and a real Hydra and asserts REST bodies, WebSocket
frames, MCP tool payloads and the agent-proxy path **as the contract documents
them** (e.g. the bare `TerminalSession` from `POST /api/sessions`, the
`{ status }` envelopes, `terminal:closed` alongside `sessions:changed`). It must
not assert anything the contract leaves unspecified — a scenario that needs an
undocumented detail is a signal to document it here first. Discovery documents
are compared against the committed goldens in
[`testdata/goldens/`](../../testdata/goldens/).

## Regenerating / validating

The spec is **hand-authored**; the server's response models are generated
from it (`go generate ./internal/api`, oapi-codegen, models only) and CI fails
on drift (`scripts/check-api-codegen.sh`). Request validation is still
hand-written in the handlers. Treat this directory as the reviewed contract.

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

Related, now resolved in both backends: Node's MCP tool schema used to
silently strip `userVerification`/`agentForward` from create/update `data`, so
endpoints were not fully editable via MCP. That was a bug, not the contract —
create/update accept and validate both fields (see
[`mcp-tools.md`](./mcp-tools.md)).

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
  third error shape. The CIMD front door (`GET /api/hydra/authorize`) is a
  fourth: having no JSON body at all, it reports failure either as an HTML error
  page (when the requested `redirect_uri` has not yet been validated against the
  client's metadata document and therefore must not be trusted as a
  destination) or as `error` / `error_description` / `state` in the query string
  of a redirect to that `redirect_uri` once it has been (RFC 6749 §4.1.2.1).
  That split is a security property, not an inconsistency to converge away.

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

### K. Host-key pinning ([#241]) exists only in the Go backend

The Node implementation never verified SSH host keys (no `hostVerifier` passed
to ssh2) and has no `hostKey` on the endpoint shape, no
`/api/endpoints/:id/host-key` routes, no `hostKey` in `SignRequestContext`, no
`host-key:mismatch` WS message, and no `host-key-mismatch` /
`host-key-cleared` audit types. Node is frozen pre-cutover and will not grow
them; the spec documents the Go behavior.

### L. The Go MCP surface is stateless and dropped the custom notifications ([#243])

Node spoke only the handshake-era protocol with per-connection
`Mcp-Session-Id` state, a standalone GET SSE stream, MCP sessions that closed
their terminal sessions on disconnect, and the custom
`notifications/shellwatch/{output_available,session_status}` methods. The Go
backend implements spec revision `2026-07-28` (plus the `2025-11-25`/
`2025-06-18` handshake eras) **statelessly**: no `Mcp-Session-Id`, GET/DELETE
405, terminal sessions owned by `(account, OAuth client)` and surviving
disconnects, custom notifications removed in every era in favour of
`shellwatch://sessions` resources over `subscriptions/listen` and
`shellwatch_read_output` `waitMs` long-polling. Node is frozen pre-cutover;
[`mcp-tools.md`](./mcp-tools.md) documents the Go behavior.

[#210]: https://github.com/rado0x54/ShellWatch/issues/210
[#243]: https://github.com/rado0x54/ShellWatch/issues/243
[#241]: https://github.com/rado0x54/ShellWatch/issues/241
[#225]: https://github.com/rado0x54/ShellWatch/issues/225
[#244]: https://github.com/rado0x54/ShellWatch/issues/244
