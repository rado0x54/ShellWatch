# shellwatch-agent

Thin SSH agent proxy that lets system SSH clients (`ssh`, `scp`, `git`) use ShellWatch-managed keys.

Listens on a local Unix socket (`SSH_AUTH_SOCK`) and relays [SSH agent protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent) frames over WebSocket to a ShellWatch server.

## Install

Pre-built binaries are attached to each [`agent/v*` release](https://github.com/rado0x54/ShellWatch/releases).

```bash
# Pick your platform from the release page, then:
curl -fsSL -o shellwatch-agent \
  https://github.com/rado0x54/ShellWatch/releases/download/agent/v0.0.1/shellwatch-agent-darwin-arm64
chmod +x shellwatch-agent
sudo mv shellwatch-agent /usr/local/bin/
```

To build from source:

```bash
cd agent-client
go build -o shellwatch-agent ./cmd/shellwatch-agent/
```

Cross-compile for other platforms:

```bash
GOOS=linux GOARCH=amd64 go build -o shellwatch-agent-linux-amd64 ./cmd/shellwatch-agent/
GOOS=linux GOARCH=arm64 go build -o shellwatch-agent-linux-arm64 ./cmd/shellwatch-agent/
```

## Quickstart

```bash
# Authorize this device via the browser. Opens https://app.shellwatch.ai
# (or whatever you pass to --server) and walks you through creating an
# agent-scoped API key. The token is persisted in the OS keyring or a
# 0600 file fallback — no plaintext config to manage.
shellwatch-agent login

# Start the daemon. Picks up the token from the credstore automatically.
shellwatch-agent

# Tell your shell where the socket lives.
eval "$(shellwatch-agent --print-env)"

# Verify.
ssh-add -l
ssh user@host
```

To use a self-hosted instance, pass `--server`:

```bash
shellwatch-agent login --server https://shellwatch.example.com
shellwatch-agent --server https://shellwatch.example.com
```

You can hold credentials for multiple instances simultaneously — `login` keys them by server URL, and the daemon looks up by whichever URL it's configured for.

To remove a stored token:

```bash
shellwatch-agent logout                     # default server
shellwatch-agent logout --server https://...  # specific server
```

`logout` only removes the local token; the API key still exists on the server. To revoke it entirely, delete it in **Settings → API Keys** at your ShellWatch instance.

## Alternative: static API key (CI / headless)

For environments where the browser-based flow isn't practical (CI runners, headless servers, automation), pass an API key directly. Generate one in **Settings → API Keys** with the `agent` scope.

```bash
# Flag form:
shellwatch-agent --api-key sw_...

# Env form:
SHELLWATCH_API_KEY=sw_... shellwatch-agent
```

Static keys take precedence over the credstore, so this works even if you've also run `login`.

## Configuration

Precedence: CLI flags > environment variables > credstore > defaults.

| Flag          | Env var                 | Description                                                  |
| ------------- | ----------------------- | ------------------------------------------------------------ |
| `--server`    | `SHELLWATCH_SERVER`     | ShellWatch server URL (default: `https://app.shellwatch.ai`) |
| `--api-key`   | `SHELLWATCH_API_KEY`    | Static API key. Skips the credstore lookup.                  |
| `--socket`    | `SHELLWATCH_AGENT_SOCK` | Unix socket path (default: auto)                             |
| `--insecure`  | —                       | Allow `ws://` (daemon) or `http://` (login) — local dev only |
| `--print-env` | —                       | Print `export SSH_AUTH_SOCK=...` and exit                    |

The default socket path uses `os.TempDir()`:

- **Linux:** `$XDG_RUNTIME_DIR/shellwatch-agent.sock` if set, otherwise `${TMPDIR:-/tmp}/shellwatch-agent-<uid>.sock`.
- **macOS:** `${TMPDIR}/shellwatch-agent-<uid>.sock` — and `$TMPDIR` is set per-user to a `/var/folders/.../T/` path by launchd, _not_ `/tmp`.

The path is stable across restarts, so it's safe to compute once in your shell profile.

## Where credentials live

`shellwatch-agent login` writes the token to whichever store is reachable on your system. The file fallback path follows Go's [`os.UserConfigDir`](https://pkg.go.dev/os#UserConfigDir) convention, so it lands in the platform-correct location:

| Platform | Primary store                             | Fallback (mode 0600)                                         |
| -------- | ----------------------------------------- | ------------------------------------------------------------ |
| macOS    | Keychain (via `security`)                 | `~/Library/Application Support/shellwatch/credentials`       |
| Linux    | libsecret D-Bus (gnome-keyring / KWallet) | `${XDG_CONFIG_HOME:-~/.config}/shellwatch/credentials`       |
| Windows  | DPAPI / Credential Manager                | `%AppData%\shellwatch\credentials` (user-only by parent ACL) |

The fallback is used when the OS keyring isn't reachable in the current session — a Mac mini you SSH'd into without a logged-in GUI user, a Linux VPS without a D-Bus session bus, or a CI runner. In those cases the token lands in the file with a one-line warning.

**On Windows, the 0600 mode bits don't actually do anything** — Go's `os.Chmod` only flips the read-only bit on Windows, not NTFS ACLs. Protection comes from `%AppData%`'s parent ACLs, which Windows configures user-only by default when the profile is created. If you've manually loosened those ACLs, the fallback file inherits the looser permissions; prefer the keyring path on Windows for any multi-user box.

If you want to inspect or back up the file directly:

```bash
# macOS:
cat "$HOME/Library/Application Support/shellwatch/credentials"

# Linux:
cat "${XDG_CONFIG_HOME:-$HOME/.config}/shellwatch/credentials"

# Windows (PowerShell):
Get-Content "$env:AppData\shellwatch\credentials"
```

The file is JSON: `{ "tokens": { "https://app.shellwatch.ai": "sw_..." } }`.

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

### macOS (`launchd` user agent)

Run `shellwatch-agent login` once first to populate the keyring, then create `~/Library/LaunchAgents/ai.shellwatch.agent.plist`:

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

(launchd does **not** expand `$HOME` or `~` in `ProgramArguments` — use a fully absolute path or the agent will fail to spawn with `EX_CONFIG (78)`.)

No `EnvironmentVariables` block is needed — the daemon reads the API key from the keyring on startup. If you're using a self-hosted instance, add a `--server` flag to `ProgramArguments`:

```xml
<key>ProgramArguments</key>
<array>
    <string>/usr/local/bin/shellwatch-agent</string>
    <string>--server</string>
    <string>https://shellwatch.example.com</string>
</array>
```

Load it:

```bash
launchctl load ~/Library/LaunchAgents/ai.shellwatch.agent.plist
launchctl kickstart -k "gui/$(id -u)/ai.shellwatch.agent"   # restart after edits
launchctl unload ~/Library/LaunchAgents/ai.shellwatch.agent.plist
```

### Linux (`systemd --user` unit)

Run `shellwatch-agent login` once first, then create `~/.config/systemd/user/shellwatch-agent.service`:

```ini
[Unit]
Description=ShellWatch SSH agent proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/shellwatch-agent
Restart=always
RestartSec=5s

[Install]
WantedBy=default.target
```

For a self-hosted server, append `--server URL` to `ExecStart`. No `Environment=` lines are needed — the daemon reads from the credstore.

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

If launchd or systemd keeps respawning the agent and eventually throttles it (`launchctl print gui/$(id -u)/ai.shellwatch.agent` shows `last exit code = 1`, or `systemctl --user status` shows repeated start failures), check the err log for two common causes:

- `another process is listening on …` — you previously started the agent manually in a terminal and the supervisor can't bind the same socket. Kill the stray process (`lsof "$SSH_AUTH_SOCK"` to find it) and the supervisor will recover.
- `no API key for …` — you haven't run `shellwatch-agent login` yet, or you're pointing at a different `--server` than you logged into. Run `login` for that server URL.

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

### OAuth flow for `login`

`shellwatch-agent login` runs an RFC 6749 + 7636 loopback PKCE flow against the server's `/oauth/authorize` endpoint:

1. Generate a PKCE verifier and S256 challenge.
2. Bind a one-shot HTTP listener on `127.0.0.1:0`.
3. Open the user's browser to `${server}/oauth/authorize?response_type=code&scope=agent&...`.
4. User logs in (passkey if required) and clicks Authorize on the consent page.
5. Server redirects to the loopback URL with a code; agent verifies state, exchanges code at `/oauth/token`.
6. Token (a long-lived `sw_…` API key) is persisted via the credstore.

The token is the same kind of API key you'd create in Settings → API Keys — `login` is a UX wrapper around the same machinery, not delegated auth with refresh tokens.

### OpenSSH extension handling

Newer OpenSSH sends `SSH_AGENTC_EXTENSION` (type 27) for session binding before requesting identities. The Go proxy handles these locally (responds with `SSH_AGENT_FAILURE`) without forwarding to the server, working around a parse bug in ssh2's `AgentProtocol` for unknown message types with payloads.

## Known limitations

- **OpenSSH 10.3+ required for passkeys.** Earlier clients reject the webauthn signature format returned by the agent. See [#36](https://github.com/rado0x54/ShellWatch/issues/36).
- **Browser session required for passkeys.** If no browser is connected to ShellWatch, passkey sign requests will fail. File keys continue to work without a browser.

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

### `no API key for <server>`

The daemon couldn't find an API key for the configured server URL. Either:

- Run `shellwatch-agent login --server <server>` to authorize via the browser, or
- Pass `--api-key` / set `SHELLWATCH_API_KEY` to a key with the `agent` scope.

If you ran `login` against a different server URL than the daemon is using, the credentials won't match. Run `login` again for the URL the daemon expects.

## Tests

```bash
go test ./...
```
