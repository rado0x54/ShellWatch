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
                                                          └─ passkeys (not yet supported, see #36)
```

1. SSH client connects to `SSH_AUTH_SOCK` and sends agent protocol messages
2. `shellwatch-agent` relays each message as a binary WebSocket frame to ShellWatch
3. ShellWatch's `AgentProtocol` handles the request (list keys, sign data)
4. Response flows back through WebSocket to the Unix socket

Each Unix socket connection gets its own WebSocket, ensuring clean state isolation between concurrent SSH clients.

### OpenSSH extension handling

Newer OpenSSH sends `SSH_AGENTC_EXTENSION` (type 27) for session binding before requesting identities. The Go proxy handles these locally (responds with `SSH_AGENT_FAILURE`) without forwarding to the server, working around a parse bug in ssh2's `AgentProtocol` for unknown message types with payloads.

## Known limitations

- **WebAuthn passkeys are not supported** through the agent proxy. OpenSSH internally canonicalizes `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` to `sk-ecdsa-sha2-nistp256@openssh.com`, making the signature format incompatible. See [#36](https://github.com/rado0x54/ShellWatch/issues/36) for details.
- **API key must have `agent` scope.** Keys created via the UI currently only get `mcp` scope. Use the `seedAdminApiKey` config option or update the key's scopes in the database.

## Tests

```bash
go test ./...
```
