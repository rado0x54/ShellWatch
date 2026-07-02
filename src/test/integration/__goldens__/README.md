<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# Golden fixtures — cross-language parity oracle

Committed, normalized captures of real Node-backend responses, used to prove the
Go rewrite (#210) reproduces the wire contract exactly (#225 item 2). They pair
with the hand-authored spec in [`docs/api/`](../../../../docs/api): the spec
says what the shape _should_ be; these goldens pin what the handlers _actually_
return, byte for byte (after normalization).

## Layout

Each `*.json` is one captured case. Generated and asserted by the
`src/test/integration/golden-*.test.ts` suites:

| Suite                 | Fixtures                                                         | Covers                                                                                                                                 |
| --------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `golden-http`         | `discovery-*`, `err-*`, `endpoints-*`, `health`                  | OAuth/RFC 9728 discovery, REST envelopes, 401/404/400 matrix                                                                           |
| `golden-mcp`          | `mcp-*`                                                          | MCP tool JSON payloads + `isError`/message shape                                                                                       |
| `golden-ws`           | `ws-*`                                                           | connect-time `sessions:changed`, `terminal:attach` reply                                                                               |
| `golden-audit`        | `audit-*`                                                        | paged `{ rows, nextCursor }`, keyset pagination, single-row, 400                                                                       |
| `golden-webauthn`     | `webauthn-*`                                                     | WebAuthn ceremony _finish_ response envelopes (self-register, login, step-up, in-account add, invite mint/redeem)                      |
| `golden-account`      | `account-*`, `keys-list`, `meta-*`, `endpoint-*`                 | current-account read/update, admin accounts + delete + export-seed, SSH-key list, `/api/version`, `/config.js`, endpoint update/delete |
| `golden-session`      | `session-*`                                                      | session-lifecycle success bodies (create → list → tail → close)                                                                        |
| `golden-credentials`  | `credentials-list`, `credential-*`, `passkey-status`, `invite-*` | passkey list/label/confirm/revoke (step-up minted), status probe, invite reads                                                         |
| `golden-hydra`        | `auth-session*`, `consent-*`, `dcr-register`                     | authorized-client list/revoke, mediated DCR, consent-approve                                                                           |
| `golden-actions-push` | `action-*`, `push-*`                                             | pending-action get/resolve/deny, Web Push subscribe/unsubscribe                                                                        |

## Normalization

Volatile per-run values are folded to stable placeholders before writing/
comparing, so both implementations diff against the same file. Rules live in
[`src/test/helpers/golden.ts`](../../helpers/golden.ts) — the Go harness must
apply the identical set:

| Placeholder     | Source                                                |
| --------------- | ----------------------------------------------------- |
| `<TS>`          | timestamp keys + any ISO-8601 value                   |
| `sess_<ID>`     | `sess_<12 hex>` session ids                           |
| `<UUID>`        | bare UUIDs (e.g. server-generated endpoint id)        |
| `<CURSOR>`      | opaque audit `nextCursor`                             |
| `<REDACTED>`    | `challenge` / `challengeId` / `token` / `stepUpToken` |
| `<FINGERPRINT>` | `SHA256:…` key fingerprints                           |
| `<PORT>`        | a `port` field equal to a per-run ssh/app port        |
| `<BASE_URL>`    | the live server origin inside a string                |

Discovery suites additionally pin `externalUrl` to a fixed host so those bodies
are stable independent of the listen port.

## Workflow

```bash
pnpm test:golden          # assert current backend matches the committed goldens
pnpm test:golden:update   # regenerate after an INTENTIONAL contract change (review the diff!)
```

A few suites fold values the `golden.ts` normalizer can't pattern-match, by hand
before capture: `<ID>` (random base64url pending-action ids) and `<OUTPUT>` (raw
terminal tail bytes). These are per-suite, documented in each suite's docblock.

## Coverage guard

The goldens are the parity oracle, so a silent gap in them (the #225 failure
mode — ~20 of 54 operationIds covered, parity generalized from the subset) is
exactly what must not recur. [`golden-coverage.ts`](../golden-coverage.ts) is a
committed manifest mapping **every** `openapi.yaml` `operationId` to its golden
fixture(s) or to an `excluded` entry with a stated reason, and
[`golden-coverage.test.ts`](../golden-coverage.test.ts) fails CI on any operation
that is neither goldened nor deliberately excluded, on stale manifest entries,
and on mapped fixtures missing from disk. Adding or renaming an operation in
`openapi.yaml` therefore forces a matching golden (or a documented exclusion) in
the same change. Current deliberate exclusions: the WebAuthn/consent `/options`
passthroughs (non-deterministic `@simplewebauthn` challenge bodies) and
`finishHydraConsent` (its `{ redirectTo }` envelope is identical to
`finishHydraLogin`/`webauthn-login-verify`).

A failing `pnpm test:golden` means the backend's observable contract changed. If
intentional, regenerate and review the JSON diff as part of the PR; if not, it's
a regression. The goldens also run as part of `pnpm test:integration` (CI).

## Using these from the Go port

The Go parity harness replays each case's request against the Go server, applies
the same normalization, and asserts equality against the same `*.json`. Keep the
placeholder set above in lockstep between the two implementations — it is the
contract, not an implementation detail.
