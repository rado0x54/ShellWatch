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
# Start the agent proxy (uses https://app.shellwatch.ai by default)
./shellwatch-agent --api-key sw_...

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

### Self-hosted server

```bash
./shellwatch-agent --server https://shellwatch.example.com --api-key sw_...
```

### Local development (HTTP)

```bash
./shellwatch-agent --server http://localhost:3000 --api-key sw_... --insecure
```

## Configuration

Precedence: CLI flags > environment variables > defaults.

| Flag          | Env var                 | Description                                                  |
| ------------- | ----------------------- | ------------------------------------------------------------ |
| `--server`    | `SHELLWATCH_SERVER`     | ShellWatch server URL (default: `https://app.shellwatch.ai`) |
| `--api-key`   | `SHELLWATCH_API_KEY`    | API key with `agent` scope (required)                        |
| `--socket`    | `SHELLWATCH_AGENT_SOCK` | Unix socket path (default: auto)                             |
| `--insecure`  | —                       | Allow `ws://` connections                                    |
| `--print-env` | —                       | Print `export SSH_AUTH_SOCK=...` and exit                    |

The default socket path uses `os.TempDir()`:

- **Linux:** `$XDG_RUNTIME_DIR/shellwatch-agent.sock` if set, otherwise `${TMPDIR:-/tmp}/shellwatch-agent-<uid>.sock`.
- **macOS:** `${TMPDIR}/shellwatch-agent-<uid>.sock` — and `$TMPDIR` is set per-user to a `/var/folders/.../T/` path by launchd, _not_ `/tmp`.

The path is stable across restarts, so it's safe to compute once in your shell profile.

## Running permanently as a background daemon

The agent is designed to run as a long-lived background process — start it once at login and forget about it. It survives laptop sleep, network changes (WiFi ↔ cellular), and brief server outages: WebSocket-level keepalive detects dead connections within ~1 minute, and the dialer reconnects with exponential backoff on the next SSH operation.

Whichever launcher you use, your shell needs to know where to find the socket. The simplest way is to ask the binary directly — it prints the path it would use:

```bash
# ~/.zshrc or ~/.bashrc
eval "$(/usr/local/bin/shellwatch-agent --print-env)"
```

Or compute it inline (note macOS `$TMPDIR` ends with a trailing slash):

```bash
# Linux
export SSH_AUTH_SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/shellwatch-agent.sock"
# macOS — launchd-set TMPDIR always ends in /, and so does the /tmp/ fallback
export SSH_AUTH_SOCK="${TMPDIR:-/tmp/}shellwatch-agent-$(id -u).sock"
```

An agent-scoped API key only authorises the proxy to _forward_ sign requests to ShellWatch — actual signing still requires a passkey touch (or a server-side file key). It is not a long-term credential, so embedding it in the unit file is fine.

### macOS (`launchd` user agent)

Create `~/Library/LaunchAgents/ai.shellwatch.agent.plist` (launchd does **not** expand `$HOME` or `~` in `ProgramArguments` — use a fully absolute path or the agent will fail to spawn with `EX_CONFIG (78)`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.shellwatch.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/shellwatch-agent</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SHELLWATCH_API_KEY</key>
        <string>sw_...</string>
        <!-- Override only if you need a self-hosted server: -->
        <!-- <key>SHELLWATCH_SERVER</key><string>https://shellwatch.example.com</string> -->
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/shellwatch-agent.out.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/shellwatch-agent.err.log</string>
</dict>
</plist>
```

`chmod 600 ~/Library/LaunchAgents/ai.shellwatch.agent.plist` so other users can't read the key.

Load it:

```bash
launchctl load ~/Library/LaunchAgents/ai.shellwatch.agent.plist
launchctl kickstart -k "gui/$(id -u)/ai.shellwatch.agent"   # restart after edits
launchctl unload ~/Library/LaunchAgents/ai.shellwatch.agent.plist
```

### Linux (`systemd --user` unit)

Create `~/.config/systemd/user/shellwatch-agent.service`:

```ini
[Unit]
Description=ShellWatch SSH agent proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/shellwatch-agent
Environment=SHELLWATCH_API_KEY=sw_...
Restart=always
RestartSec=5s

[Install]
WantedBy=default.target
```

`chmod 600 ~/.config/systemd/user/shellwatch-agent.service` so other users can't read the key.

Enable and start it:

```bash
systemctl --user daemon-reload
systemctl --user enable --now shellwatch-agent.service
sudo loginctl enable-linger "$USER"   # so the agent survives logout
```

Manage it:

```bash
systemctl --user status shellwatch-agent
systemctl --user restart shellwatch-agent
journalctl --user -u shellwatch-agent -f
```

### Verifying it's running

```bash
# Confirm the agent answers (lists available keys)
ssh-add -l

# Watch the logs
# macOS:
tail -f /tmp/shellwatch-agent.err.log
# Linux:
journalctl --user -u shellwatch-agent -f
```

If `ssh-add -l` returns `Could not open a connection to your authentication agent`, check that `SSH_AUTH_SOCK` is exported in the shell you're using.

If launchd or systemd keeps respawning the agent and eventually throttles it (`launchctl print gui/$(id -u)/ai.shellwatch.agent` shows `last exit code = 1`, or `systemctl --user status` shows repeated start failures), check the err log for `another process is listening on …`. That happens when you previously started the agent manually in a terminal and the supervisor can't bind the same socket. Kill the stray process (`lsof "$SSH_AUTH_SOCK"` to find it) and the supervisor will recover on its next restart.

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
