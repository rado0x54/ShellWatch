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

| Suite          | Fixtures                                        | Covers                                                           |
| -------------- | ----------------------------------------------- | ---------------------------------------------------------------- |
| `golden-http`  | `discovery-*`, `err-*`, `endpoints-*`, `health` | OAuth/RFC 9728 discovery, REST envelopes, 401/404/400 matrix     |
| `golden-mcp`   | `mcp-*`                                         | MCP tool JSON payloads + `isError`/message shape                 |
| `golden-ws`    | `ws-*`                                          | connect-time `sessions:changed`, `terminal:attach` reply         |
| `golden-audit` | `audit-*`                                       | paged `{ rows, nextCursor }`, keyset pagination, single-row, 400 |

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

A failing `pnpm test:golden` means the backend's observable contract changed. If
intentional, regenerate and review the JSON diff as part of the PR; if not, it's
a regression. The goldens also run as part of `pnpm test:integration` (CI).

## Using these from the Go port

The Go parity harness replays each case's request against the Go server, applies
the same normalization, and asserts equality against the same `*.json`. Keep the
placeholder set above in lockstep between the two implementations — it is the
contract, not an implementation detail.
