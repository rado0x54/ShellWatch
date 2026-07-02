<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# `/agent-proxy` WebSocket protocol

Wire contract for the SSH-agent bridge between the `shellwatch-agent` client
(`agent-client/`, Go) and the ShellWatch server. Frozen for the Go rewrite
([#210]/[#232]) from the current implementation:
`src/agent-socket/agent-proxy-route.ts` + `socket-agent-handler.ts` (server)
and `agent-client/internal/proxy/proxy.go` (client). Documented **as-is**;
divergences must change code + this doc together.

```
ssh(1) ──unix socket──▶ shellwatch-agent ──WSS /agent-proxy──▶ ShellWatch
                          (one WS per SSH client connection)      │
                                                                  ├─ file keys   (approval-gated)
                                                                  └─ passkeys    (browser WebAuthn)
```

## Availability

- Endpoint: `GET /agent-proxy` (HTTP → WebSocket upgrade).
- Registered only when `agentSocket.proxyEnabled: true` (config; default
  `false`). When disabled, the path 404s and mediated DCR
  (`POST /api/hydra/register`) refuses to grant the `agent` scope.

## Authentication

- `Authorization: Bearer <token>` header on the upgrade request — a Hydra
  opaque access token with scope `agent`, introspected pre-upgrade by the
  bearer gate. (Native client; the `/ws` `Sec-WebSocket-Protocol` fallback
  does **not** apply here.)
- Failures are plain HTTP responses before the upgrade (401). The IP
  allowlist (`security.allowedNetworks`) applies to `/mcp` only, **not** to
  `/agent-proxy` — despite older prose suggesting otherwise.

### Client-metadata headers (optional, self-reported)

| Header                  | Content (client convention)        |
| ----------------------- | ---------------------------------- |
| `X-ShellWatch-Hostname` | `os.Hostname()`                    |
| `X-ShellWatch-OS`       | `GOOS/GOARCH`, e.g. `darwin/arm64` |
| `X-ShellWatch-Version`  | agent build version                |

Server-side each value is sanitized — ASCII control characters
(`0x00–0x1F`, `0x7F`) stripped, clamped to **128 chars**, empty → absent
(`src/util/sanitize-client-info.ts`) — and surfaced on `/sign/:id` in a
separate "self-reported" block so approvers don't mistake spoofable data for
authoritative identity. Absent headers are fine; the UI hides them.

## Framing

- **Binary WebSocket messages only.** One binary message = **one complete
  SSH agent protocol frame**: 4-byte big-endian payload length + payload
  (the length prefix is part of the message). No batching, no splitting.
- A text message closes the connection with code **4002**
  (`Only binary messages are accepted`).
- Strictly sequential request/response: the client writes one request frame
  and waits for exactly one response frame before sending the next. The
  server never sends unsolicited frames.
- Size: the client refuses frames with payloads over **256 KiB**; the server
  imposes no explicit cap (ssh2 `AgentProtocol` internal limits apply).
  Treat 256 KiB as the practical contract.
- Keepalive: the **client** pings every 30 s and treats 60 s of silence as a
  dead link. The server sends no pings (the `ws` library auto-answers pongs).
  A Go server must keep answering pings; it need not originate them.

## SSH agent protocol semantics

The payload is the standard SSH agent protocol
([draft-miller-ssh-agent](https://datatracker.ietf.org/doc/draft-miller-ssh-agent/)).
Server-supported requests:

| Request                              | Response                                                                                                                                                             |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SSH_AGENTC_REQUEST_IDENTITIES` (11) | `SSH_AGENT_IDENTITIES_ANSWER` (12) — all discovered file keys (key directory) **plus** the account's passkeys as `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` blobs |
| `SSH_AGENTC_SIGN_REQUEST` (13)       | `SSH_AGENT_SIGN_RESPONSE` (14) on approval, `SSH_AGENT_FAILURE` (5) on deny/expiry/error                                                                             |
| anything else                        | `SSH_AGENT_FAILURE` (5)                                                                                                                                              |

`SSH_AGENTC_EXTENSION` (27): the **client answers `SSH_AGENT_FAILURE`
locally and does not forward it** (OpenSSH sends a session-bind extension
before listing identities; failing it is the correct "unsupported" reply,
and forwarding it trips a parse-buffer bug in ssh2's `AgentProtocol`). A Go
server should nonetheless tolerate a forwarded type-27 frame by replying
`FAILURE` — old clients aren't guaranteed to filter.

### Human-in-the-loop signing

Every `SIGN_REQUEST` — passkey **and** file key — creates a `PendingAction`
(60 s TTL) and notifies the account's channels (WS toast, Web Push) with a
`/sign/:id` deep link; there is no silent auto-sign on this surface.

- Approved passkey sign → WebAuthn assertion converted to the PROTOCOL.u2f
  wire signature (`src/webauthn/signature-format.ts`) → `SIGN_RESPONSE`.
- Approved file-key sign → server signs with the file key → `SIGN_RESPONSE`.
- Denied / expired (60 s) / cancelled → `SSH_AGENT_FAILURE`. The WebSocket
  **stays open**; the SSH client simply tries its next identity.
- Consequence: a `SIGN_REQUEST` response can legitimately take up to ~60 s.
  Clients must not apply short read timeouts to in-flight sign requests
  (the client's 60 s pong-based liveness window is compatible: pings keep
  flowing while the request is pending).

### `webauthn-sk-*` / OpenSSH 10.3 canonicalization

Passkey identities require OpenSSH **10.3+** on the calling side (#36).
OpenSSH canonicalizes `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` to
`sk-ecdsa-sha2-nistp256@openssh.com` in `SIGN_REQUEST` key blobs. The server
therefore:

- accepts `sk-ecdsa` blobs as webauthn keys when the key's **application**
  string is not `"ssh:"` (a web origin ⇒ webauthn; `"ssh:"` ⇒ standard
  FIDO2), and always advertises the `webauthn-`-prefixed type in
  `IDENTITIES_ANSWER`;
- emits the webauthn PROTOCOL.u2f signature layout in `SIGN_RESPONSE` (raw
  signature bytes after the algorithm string — no extra string wrapper).

Today this lives in the ssh2 fork ([rado0x54/ssh2#1]); in the Go port it is
owned by `internal/signing` + the `agent.ExtendedAgent` implementation.

## Close codes

| Code                | Sender | Meaning                                                   |
| ------------------- | ------ | --------------------------------------------------------- |
| 1011                | server | internal auth state missing (defensive; should not occur) |
| 4000                | server | agent-protocol stream error (malformed frame)             |
| 4002                | server | non-binary message received                               |
| 1000/1001/1005/1006 | client | SSH client disconnected / shutdown / network loss         |

## Client lifecycle (informative)

Conventions of the reference client, not server requirements: one WebSocket
per SSH client connection (protocol-state isolation); the WS is dialed
lazily on the first non-extension frame; transient dial failures retry with
exponential backoff (500 ms → 30 s cap, 60 s total budget); non-transient
failures (401/403/404, TLS validation) abort immediately; `https://` is
required unless `--insecure`.

[#210]: https://github.com/rado0x54/ShellWatch/issues/210
[#232]: https://github.com/rado0x54/ShellWatch/issues/232
[rado0x54/ssh2#1]: https://github.com/rado0x54/ssh2/pull/1
