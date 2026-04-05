# shellwatch-agent

Thin SSH agent proxy that lets system SSH clients (`ssh`, `scp`, `git`) use ShellWatch-managed keys.

Listens on a local Unix socket (`SSH_AUTH_SOCK`) and relays [SSH agent protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent) frames over WebSocket to a ShellWatch server.

## Build

Requires Go 1.21+.

```bash
cd agent-client
go build -o shellwatch-agent ./cmd/shellwatch-agent/
```

Cross-compile for other platforms:

```bash
GOOS=linux GOARCH=amd64 go build -o shellwatch-agent-linux-amd64 ./cmd/shellwatch-agent/
GOOS=linux GOARCH=arm64 go build -o shellwatch-agent-linux-arm64 ./cmd/shellwatch-agent/
```

## Usage

```bash
# Start the agent proxy
./shellwatch-agent --server https://shellwatch.example.com --api-key sw_...

# In another terminal (or add to your shell profile)
export SSH_AUTH_SOCK=/tmp/shellwatch-agent-501.sock  # path printed on startup

# Verify
ssh-add -l

# Connect
ssh user@host
```

### Print socket path for shell eval

```bash
eval $(./shellwatch-agent --print-env)
```

### Local development (HTTP)

```bash
./shellwatch-agent --server http://localhost:3000 --api-key sw_... --insecure
```

## Configuration

Precedence: CLI flags > environment variables > defaults.

| Flag          | Env var                 | Description                               |
| ------------- | ----------------------- | ----------------------------------------- |
| `--server`    | `SHELLWATCH_SERVER`     | ShellWatch server URL (required)          |
| `--api-key`   | `SHELLWATCH_API_KEY`    | API key with `agent` scope (required)     |
| `--socket`    | `SHELLWATCH_AGENT_SOCK` | Unix socket path (default: auto)          |
| `--insecure`  | —                       | Allow `ws://` connections                 |
| `--print-env` | —                       | Print `export SSH_AUTH_SOCK=...` and exit |

The default socket path is `$XDG_RUNTIME_DIR/shellwatch-agent.sock` if set, otherwise `/tmp/shellwatch-agent-<uid>.sock`.

## How it works

```
ssh client ──► Unix socket ──► shellwatch-agent ──WSS──► ShellWatch /agent-proxy
                                                          │
                                                          ├─ file keys (auto-sign)
                                                          └─ passkeys (browser-signed via WebAuthn)
```

1. SSH client connects to `SSH_AUTH_SOCK` and sends agent protocol messages
2. `shellwatch-agent` relays each message as a binary WebSocket frame to ShellWatch
3. ShellWatch's `AgentProtocol` handles the request (list keys, sign data)
4. Response flows back through WebSocket to the Unix socket

Each Unix socket connection gets its own WebSocket, ensuring clean state isolation between concurrent SSH clients.

### WebAuthn passkey support

Passkeys registered in ShellWatch are exposed alongside file keys. When the SSH client requests a signature for a passkey, ShellWatch forwards the challenge to a connected browser session via the signing bridge. The user confirms by touching their security key (YubiKey, etc.), and the WebAuthn assertion flows back through the agent proxy to the SSH client.

**Requires OpenSSH 10.3+** on the client. Earlier versions canonicalize `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` to `sk-ecdsa-sha2-nistp256@openssh.com` and reject the mismatched signature type from the agent. OpenSSH 10.3 ([released 2026-04-02](https://www.openssh.com/releasenotes.html)) relaxes the signature type check for FIDO keys, allowing the webauthn signature format to pass through. See [#36](https://github.com/rado0x54/ShellWatch/issues/36) for the full analysis.

The **server** does not need 10.3 for plain (non-cert) webauthn keys — the verifier already reads the algorithm from the signature blob and dispatches to the webauthn path.

A browser session must be open in ShellWatch for passkey signing to work. If no browser is connected, only file keys are available.

### OpenSSH extension handling

Newer OpenSSH sends `SSH_AGENTC_EXTENSION` (type 27) for session binding before requesting identities. The Go proxy handles these locally (responds with `SSH_AGENT_FAILURE`) without forwarding to the server, working around a parse bug in ssh2's `AgentProtocol` for unknown message types with payloads.

## Known limitations

- **OpenSSH 10.3+ required for passkeys.** Earlier clients reject the webauthn signature format returned by the agent. See [#36](https://github.com/rado0x54/ShellWatch/issues/36).
- **Browser session required for passkeys.** If no browser is connected to ShellWatch, passkey sign requests will fail. File keys continue to work without a browser.
- **API key must have `agent` scope.** Keys created via the UI currently only get `mcp` scope. Use the `seedAdminApiKey` config option or update the key's scopes in the database.

## Troubleshooting

### `agent key returned incorrect signature type` / `signature algorithm not supported`

```
agent key ECDSA-SK SHA256:... returned incorrect signature type
sign_and_send_pubkey: signing failed for ECDSA-SK "" from agent: signature algorithm not supported
```

Your SSH client is older than 10.3. Pre-10.3 OpenSSH rejects the `webauthn-sk-ecdsa` signature returned by the agent because it expects `sk-ecdsa` (due to internal algorithm canonicalization). The client may prompt for your security key **twice** before failing — the agent protocol has no way to detect the client version, so both attempts complete the full WebAuthn flow before the client rejects the response.

**Fix:** upgrade to OpenSSH 10.3+. Check your version with `ssh -V`. On macOS, `/usr/bin/ssh` ships an older version — use the Homebrew version (`brew install openssh`) which is 10.3+.

File-based keys are unaffected and work with any OpenSSH version.

### `No browser session available for WebAuthn signing`

The agent proxy needs a browser tab open in ShellWatch to forward passkey signing requests. Open the ShellWatch UI, then retry.

## Tests

```bash
go test ./...
```
