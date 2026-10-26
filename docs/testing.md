<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# Testing

ShellWatch has three layers of automated tests. The first two run in-process
and need nothing but a Go toolchain (server) or Node (client); the third runs
the **built server binary** against a **real OpenSSH `sshd`** and a **real Ory
Hydra** in Docker.

| Layer  | Command         | What runs                                                                                                                                                                                                     | Where                              |
| ------ | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| Server | `go test ./...` | Unit tests next to the code; in-process integration suites on `httptest` against a **gliderlabs/ssh** target and a **fake Hydra** (`internal/hydratest`); golden parity fixtures + operationId coverage guard | `internal/**`, `testdata/goldens/` |
| Client | `pnpm test`     | Vitest over the Svelte stores (`foo.ts` → `foo.test.ts`)                                                                                                                                                      | `client/src/**`                    |
| E2E    | `pnpm test:e2e` | the `shellwatch` binary as a child process against **real `sshd`** + **real Hydra**, driven only over the wire                                                                                                | `e2e/`                             |

The in-process layers are documented in [`CLAUDE.md`](../CLAUDE.md#testing) and
the goldens in [`testdata/goldens/README.md`](../testdata/goldens/README.md).
This page is about the e2e suite ([#244]).

## E2E suite

### What it is

A black-box test of the backend. Nothing in `e2e/` imports server code — the
suite reaches the server only through its network ports (REST, `/ws`, `/mcp`,
`/agent-proxy`), exactly like the web UI, an MCP client and the
`shellwatch-agent` binary do. Its own TypeScript helpers live in `e2e/lib/`:
the fake WebAuthn authenticator (#162), the MCP client wrapper, the test log,
and the golden normalizer (kept in lockstep with `internal/golden`).

Why it exists: every in-process integration test talks to a gliderlabs/ssh
server written with the same library as the client, and to a fake Hydra. Real
`sshd` behaviour — algorithm negotiation, PTY semantics, `authorized_keys`
handling, `PubkeyAcceptedAlgorithms`, **`webauthn-sk` signature verification**,
agent-forwarding channels, `LoginGraceTime` — and the real authorization-code

- PKCE + consent + introspection flow are only exercised here. The suite was
  written against the Node backend and carried over unchanged to the Go server
  (#210), which is what makes it a backend-independent conformance check.

### Layout

```
e2e/
  vitest.e2e.config.ts      separate vitest project (never part of pnpm test)
  docker-compose.e2e.yml    sshd-modern, sshd-stable, hydra
  sshd/                     Dockerfile.modern (OpenSSH >= 10.3, alpine:edge, webauthn-sk)
                            Dockerfile.stable (debian:stable OpenSSH), sshd_config,
                            entrypoint.sh, hostkeys/ (committed throwaway host keys)
  hydra/hydra.e2e.yml       issuer http://127.0.0.1:4544, login/consent → the server under test
  harness/
    env.ts                  fixed ports + addresses (see below)
    server.ts               spawn the `shellwatch` binary, wait for /health, collect logs
    config.ts               writes the server's config.yaml
    identity.ts             fake passkey → COSE hex (seed) + OpenSSH webauthn-sk line; ssh-keygen file key
    oauth.ts                headless authorization_code + PKCE against Hydra (cookie jar, redirects,
                            passkey login + consent provider calls), DCR, refresh, revoke, introspect, step-up
    sshd.ts                 docker compose exec / logs --since / restart
    clients.ts              REST wrapper, /ws client, approval helpers, MCP client
    agent.ts                Go shellwatch-agent daemon + host `ssh`, headless `login`
    scenario.ts             per-scenario bootstrap (fresh server + seeded admin + keys installed + ui token)
    out.ts                  failure dumps into e2e/out/<scenario>/
  lib/                      fake authenticator, MCP client wrapper, test log, golden normalizer
  scenarios/*.e2e.test.ts   one file = one fresh server
  scripts/ensure-build.mjs  builds web/dist when stale + the server binary into out/bin/
  out/                      git-ignored: server.log, compose logs, junit.xml, built binaries
```

### Addresses

Everything binds to `127.0.0.1`. Ports avoid the dev compose (Hydra on
4444/4445) so the suite can run next to a local stack.

| Service              | Address                             |
| -------------------- | ----------------------------------- |
| server under test    | `127.0.0.1:3100` (`externalUrl`)    |
| `sshd-modern`        | `127.0.0.1:2322` — OpenSSH ≥ 10.3   |
| `sshd-stable`        | `127.0.0.1:2323` — debian stable    |
| Hydra public / admin | `127.0.0.1:4544` / `127.0.0.1:4545` |

`sshd` users: `filekey` (ed25519 file key) and `passkey` (the fake
authenticator's `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` key — modern
image only). Both `authorized_keys` are installed at test time via
`docker compose exec`, so every run uses fresh key material.

### Running locally

Requirements: Docker (with Compose v2), Go (server + agent; the harness builds
`shellwatch-agent` if `agent-client/shellwatch-agent` is absent), Node + pnpm
(client build, vitest), OpenSSH `ssh`/`ssh-keygen` on the host.

```bash
pnpm e2e:up           # build images, start sshd-modern + sshd-stable + hydra, wait for health
pnpm test:e2e         # builds web/dist if stale + the server binary, runs every scenario
pnpm e2e:down         # tear down (in-memory Hydra, nothing persists)

pnpm test:e2e:logs    # compose logs
E2E_SSHD=modern pnpm test:e2e   # one image only (CI runs one leg per image)
E2E_SKIP_BUILD=1 E2E_SERVER_BIN=./shellwatch pnpm test:e2e  # use a binary you built
```

A single scenario: `npx vitest run --config e2e/vitest.e2e.config.ts e2e/scenarios/mcp.e2e.test.ts`.

Environment knobs: `E2E_SSHD` (`modern|stable|both`, default both),
`E2E_SKIP_BUILD=1`, `E2E_SERVER_BIN` (path to a prebuilt server binary),
`E2E_AGENT_BIN` (path to a prebuilt agent),
`E2E_AGENT_LOGIN=1` (force the `shellwatch-agent login` scenario, which is
Linux-only by default because the agent would otherwise write to the macOS
Keychain).

Runtime: about 100 s for both images on a laptop (plus image build on the
first `pnpm e2e:up`); the two slow tests are the pending-action expiry (waits
out the 60 s TTL) and the idle janitor.

### The identity model

No browser is involved.

1. `identity.ts` generates a P-256 key and wraps it in the fake authenticator
   (`e2e/lib/fake-authenticator.ts`). It also derives the COSE key
   (hex) and the OpenSSH `webauthn-sk-*` authorized_keys line from the public
   key — independently of the server's own derivation, which the
   passkey-signing scenario then compares against `GET /api/webauthn/credentials`.
2. The COSE key is seeded as the admin's passkey through `seedAdminPasskeys`
   in the generated `config.yaml`, so the first boot has an admin.
3. `oauth.ts` performs the real flow against Hydra: `GET /oauth2/auth` →
   redirect to ShellWatch's login page → `POST /api/hydra/login/options` →
   assertion from the fake authenticator → `POST /api/hydra/login/verify` →
   consent (auto for the SPA client; `POST /api/hydra/consent/approve` after a
   fresh login, or `consent/options` + `consent/verify` with a passkey when
   Hydra remembered the login) → callback → `POST /oauth2/token` with PKCE.
   The result is a real `ui` bearer; third-party clients (`mcp`, `agent`) go
   through mediated DCR (`POST /api/hydra/register`) first.
4. For SSH signing, approvals are driven the way `/sign/:id` does it: the
   `sign:request` WS frame carries the challenge (standard base64 of the SSH
   data-to-sign); the fake authenticator signs it with `origin: https://<rpId>`,
   producing the clientDataJSON prefix OpenSSH's webauthn verifier
   reconstructs, and the result goes to `POST /api/actions/:id/resolve`.
   File-key approvals (`key-approve`) are a bodyless resolve.

Note that in production **every** endpoint authentication is approval-gated,
file keys included — the harness's `openSession()` runs the REST call and the
approval concurrently.

### Scenarios

| File                            | sshd   | Covers                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `session-lifecycle.e2e.test.ts` | both   | endpoint → session (key approval) → WS attach → `$SSH_CONNECTION` → `exit` → `closed` + audit; `terminal:resize` vs `stty size`; server push; concurrent sessions; unknown user / wrong key; sshd restart                                                                                                                                                                       |
| `idle-timeout.e2e.test.ts`      | first  | `sessions.idleTimeoutMinutes` janitor → `closeReason: idle-timeout`, sshd sees the disconnect                                                                                                                                                                                                                                                                                   |
| `passkey-signing.e2e.test.ts`   | modern | webauthn-sk signature accepted by sshd (`Accepted publickey … ECDSA-SK`); UV-required rejects a UV-less assertion; deny; 60 s expiry before `LoginGraceTime`; derived key line parity                                                                                                                                                                                           |
| `agent-forwarding.e2e.test.ts`  | modern | `ssh-add -L` inside the session lists both keys; second hop `ssh passkey@localhost` → `agent-forwarding` sign request; `agentForward: false` → no agent                                                                                                                                                                                                                         |
| `identity-skip.e2e.test.ts`     | modern | a user with **two** authorized keys: deny the file-key approval, approve the passkey → login succeeds (#91 skip semantics) on endpoint-auth, forwarding and proxy, with no signed attempt for the denied key on any path; asserted on sshd's log                                                                                                                                |
| `agent-proxy.e2e.test.ts`       | modern | Go agent with an `agent`-scoped Hydra token; host `ssh` via file key (and passkey when host OpenSSH ≥ 10.3); deny; authorized-client listing; headless `shellwatch-agent login` (Linux)                                                                                                                                                                                         |
| `mcp.e2e.test.ts`               | first  | official SDK client with a DCR+PKCE token: endpoints CRUD, create session (approval), send_keys, read_output offsets, notification, close; audit `source: mcp` + client name/version; cross-account isolation                                                                                                                                                                   |
| `hydra.e2e.test.ts`             | —      | discovery vs committed goldens and vs Hydra's own metadata; remembered-login/consent branches; DCR policy; refresh rotation + reuse detection; revocation; step-up revoke-all                                                                                                                                                                                                   |
| `cimd.e2e.test.ts`              | —      | CIMD front door: discovery flags; non-URL `client_id` passthrough byte-for-byte; every rejection path (draft §3 URL rules, SSRF destinations, unresolvable host) renders instead of redirecting and writes nothing to Hydra; the registration log (DCR `registered` row + Hydra `metadata.shellwatch.origin`, rejection rows, admin-only 403, keyset paging, filter validation) |

**Not covered end to end: the CIMD happy path** (fetch a metadata document →
provision the Hydra client → token → `/mcp`). The server would have to trust a
throwaway CA for a document served from the harness, and `SSL_CERT_FILE` — the
obvious hook — is ignored by Go on macOS: `root_unix.go` excludes darwin, so
Security.framework decides and the variable has no effect. Verified:

```
macOS host, no SSL_CERT_FILE      -> REJECTED (x509: "127.0.0.1" certificate is not trusted)
macOS host, SSL_CERT_FILE=ca.pem  -> REJECTED   # ignored
```

A cross-platform hook (an `extraCaBundlePath`-style config option feeding the
fetcher's root pool) would close this; until then the fetch-and-provision path
is covered by `internal/hydra/cimd_test.go` and
`internal/httpserver/cimd_frontdoor_test.go`, which serve a document from
`httptest` and inject the test CA directly.

### Adding a scenario

1. Create `e2e/scenarios/<name>.e2e.test.ts`. In `beforeAll` call
   `bootScenario({ scenario: "<name>", targets: [...] })` — it starts a fresh
   server (fresh SQLite + key directory), seeds the admin passkey, installs the
   keys on the requested sshd targets and logs in through Hydra. Call
   `sc.stop()` in `afterAll`.
2. Add `recordScenario("<name>", () => sc?.server)` at the top of the
   `describe` so failures dump `server.log` + compose logs into
   `e2e/out/<name>/`. Use `rec.mark()` before an action and
   `logsSince(target, since)` to assert on sshd's log for that window.
3. Use `describe.skipIf(!modernEnabled())` for anything that needs
   `webauthn-sk`, and `describe.each(sshdTargets())` for file-key behaviour
   that should hold on every image.
4. Assert only what the wire contract in [`docs/api/`](./api/README.md)
   specifies. Where the suite reads a fixture, it reads the committed goldens
   rather than importing server types.

### CI

The `E2E (sshd modern|stable)` job in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs `pnpm build`
(client + server binary) and builds the agent, runs `pnpm e2e:up`, then
`pnpm test:e2e` with `E2E_SSHD` set per leg and `E2E_SERVER_BIN` pointing at
the built binary, and uploads `e2e/out/**` on failure. It is not part of
`go test` or `pnpm test`; the root `vitest.config.ts` excludes `e2e/**`.

[#244]: https://github.com/rado0x54/ShellWatch/issues/244
