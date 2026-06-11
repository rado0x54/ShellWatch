# shellwatch-agent

Thin SSH agent proxy that lets system SSH clients (`ssh`, `scp`, `git`) use ShellWatch-managed keys.

Listens on a local Unix socket (`SSH_AUTH_SOCK`) and relays [SSH agent protocol](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent) frames over WebSocket to a ShellWatch server.

## Install

### Homebrew (macOS, Linux)

```bash
brew install rado0x54/tap/shellwatch-agent
```

The tap lives at [rado0x54/homebrew-tap](https://github.com/rado0x54/homebrew-tap); brew auto-derives the URL from the conventional `homebrew-` prefix, so no separate `brew tap` step is needed. The formula bundles a `service do` block, so `brew services start shellwatch-agent` works out of the box (see [Running permanently](#running-permanently-as-a-background-daemon) below).

> **Currently 404s** while [rado0x54/ShellWatch](https://github.com/rado0x54/ShellWatch) is private — anonymous HTTP can't fetch release binaries from a private repo. Will work once the upstream goes public; tracked on issues #35 and #147.

### Manual download

Pre-built binaries are attached to each [`agent/v*` release](https://github.com/rado0x54/ShellWatch/releases).

```bash
# Pick your platform from the release page, then:
curl -fsSL -o shellwatch-agent \
  https://github.com/rado0x54/ShellWatch/releases/download/agent/v0.0.1/shellwatch-agent-darwin-arm64
chmod +x shellwatch-agent
sudo mv shellwatch-agent /usr/local/bin/
```

### From source

```bash
cd agent-client
go build -o shellwatch-agent ./cmd/shellwatch-agent/
```

Cross-compile for other platforms:

```bash
GOOS=linux GOARCH=amd64 go build -o shellwatch-agent-linux-amd64 ./cmd/shellwatch-agent/
GOOS=linux GOARCH=arm64 go build -o shellwatch-agent-linux-arm64 ./cmd/shellwatch-agent/
GOOS=windows GOARCH=amd64 go build -o shellwatch-agent-windows-amd64.exe ./cmd/shellwatch-agent/
```

On Windows the proxy listens on a named pipe instead of a Unix socket — default `\\.\pipe\openssh-ssh-agent`, which is the same path stock OpenSSH for Windows looks for. See [Windows](#windows) below for usage.

## Quickstart

```bash
# Authorize this device. Opens the browser for a passkey login (the same
# loopback authorization_code + PKCE flow an MCP client uses).
shellwatch-agent login
# The resulting refresh token is persisted in the OS keyring or a 0600 file
# fallback — no plaintext config. The daemon mints + refreshes short-lived
# `agent`-scoped access tokens from it automatically.

# Start the daemon. Picks up the credentials from the credstore automatically.
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

To remove stored credentials:

```bash
shellwatch-agent logout                     # default server
shellwatch-agent logout --server https://...  # specific server
```

`logout` only removes the local credentials; it does not revoke the grant server-side. To revoke remotely, sign out / revoke the device's sessions in ShellWatch.

## Alternative: static bearer token (CI / headless)

There is no non-interactive login (a Device Authorization Grant is a planned follow-up). For a short-lived headless run you can mint an `agent`-scoped access token out-of-band and pass it directly:

```bash
# (Requires an existing browser-obtained refresh token, or a future device flow.)
shellwatch-agent --api-key "$TOKEN"
SHELLWATCH_API_KEY="$TOKEN" shellwatch-agent
```

A static token takes precedence over the credstore. Such tokens are short-lived and not refreshed — for a long-running daemon, use `login`.

## Configuration

Precedence: CLI flags > environment variables > credstore > defaults.

| Flag          | Env var                 | Description                                                  |
| ------------- | ----------------------- | ------------------------------------------------------------ |
| `--server`    | `SHELLWATCH_SERVER`     | ShellWatch server URL (default: `https://app.shellwatch.ai`) |
| `--api-key`   | `SHELLWATCH_API_KEY`    | Static bearer token. Skips the credstore lookup.             |
| `--socket`    | `SHELLWATCH_AGENT_SOCK` | Unix socket path (default: auto)                             |
| `--insecure`  | —                       | Allow `ws://` (daemon) or `http://` (login) — local dev only |
| `--print-env` | —                       | Print `export SSH_AUTH_SOCK=...` and exit                    |

The default listener path is platform-specific:

- **Linux:** `$XDG_RUNTIME_DIR/shellwatch-agent.sock` if set, otherwise `${TMPDIR:-/tmp}/shellwatch-agent-<uid>.sock`.
- **macOS:** `${TMPDIR}/shellwatch-agent-<uid>.sock` — and `$TMPDIR` is set per-user to a `/var/folders/.../T/` path by launchd, _not_ `/tmp`.
- **Windows:** `\\.\pipe\openssh-ssh-agent` (a named pipe, not a Unix socket). Matches the path stock OpenSSH for Windows expects, so `ssh.exe` finds it with no `SSH_AUTH_SOCK` set.

The path is stable across restarts, so it's safe to compute once in your shell profile.

## Windows

`shellwatch-agent` runs natively on Windows 10/11. The daemon listens on a named pipe instead of a Unix socket; the credstore uses DPAPI via the OS Credential Manager (with a `%AppData%\shellwatch\credentials` 0600-style fallback when the keyring isn't reachable).

There's no Homebrew or service-installer integration yet — run the binary directly, or wrap it with `nssm` / `sc.exe` if you want it to start at logon. Service installation is tracked on a follow-up to #175.

```powershell
# One-time browser login (passkey)
.\shellwatch-agent.exe login

# Start the daemon (foreground)
.\shellwatch-agent.exe

# In another shell — verify
ssh-add -l
ssh user@host
```

The default pipe path matches what `ssh.exe` looks for, so no `SSH_AUTH_SOCK` is needed. If you do want to set it (e.g. for cross-shell scripts), `--print-env` emits PowerShell-friendly syntax:

```powershell
Invoke-Expression (& .\shellwatch-agent.exe --print-env)
```

If the built-in `ssh-agent` Windows service is also running, it will own the same pipe path and `shellwatch-agent` will fail to bind. Stop and disable it first:

```powershell
Stop-Service ssh-agent
Set-Service ssh-agent -StartupType Disabled
```

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

### Homebrew (`brew services`)

If you installed via the [Homebrew tap](#homebrew-macos-linux), the formula's `service do` block already declares the daemon to Homebrew. Authorize once, then start the service:

```bash
shellwatch-agent login            # browser passkey login; refresh token lands in keyring
brew services start shellwatch-agent
```

Homebrew translates the formula's service definition to a launchd plist on macOS (`~/Library/LaunchAgents/homebrew.shellwatch-agent.plist`) and a systemd-user unit on Linux (`~/.config/systemd/user/homebrew.shellwatch-agent.service`), then loads it. The daemon picks up its credentials from the keyring on startup — no plaintext secret in the generated unit. Manage it with the usual `brew services` commands:

```bash
brew services list                         # status
brew services restart shellwatch-agent
brew services stop shellwatch-agent
```

Logs land in `${HOMEBREW_PREFIX}/var/log/shellwatch-agent.{log,err.log}` (e.g. `/opt/homebrew/var/log/...` on Apple Silicon, `/usr/local/var/log/...` on Intel macs, `/home/linuxbrew/.linuxbrew/var/log/...` on Linux).

The Homebrew service uses the default server URL (`https://app.shellwatch.ai`). Self-hosted instances need to fall back to the manual launchd / systemd setup below — letting Homebrew thread a custom `--server` flag through is on the roadmap but not implemented yet.

### macOS (`launchd` user agent) — manual setup

Use this if you didn't install via the Homebrew tap, or if you need a custom `--server` flag the brew service block can't express today. Run `shellwatch-agent login` once first to populate the keyring, then create `~/Library/LaunchAgents/ai.shellwatch.agent.plist`:

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

No `EnvironmentVariables` block is needed — the daemon reads its credentials from the keyring on startup. If you're using a self-hosted instance, add a `--server` flag to `ProgramArguments`:

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

### Linux (`systemd --user` unit) — manual setup

Use this if you didn't install via the Homebrew tap, or if you need a custom `--server` flag the brew service block can't express today. Run `shellwatch-agent login` once first, then create `~/.config/systemd/user/shellwatch-agent.service`:

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
- `no credentials for …` — you haven't run `shellwatch-agent login` yet, or you're pointing at a different `--server` than you logged into. Run `login` for that server URL.

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

`shellwatch-agent login` runs a loopback `authorization_code` + PKCE flow (RFC 6749 + 7636 + 8252) against the ShellWatch instance's Ory Hydra — the same flow an MCP client uses:

1. Discover endpoints from `${server}/.well-known/oauth-authorization-server`.
2. Register a public loopback client via mediated DCR (`/oauth/register`).
3. Open the browser to Hydra's authorize endpoint → ShellWatch's passkey login + consent providers.
4. Catch the redirect on a loopback listener, exchange the code (PKCE) for an `agent`-scoped access token + refresh token (`offline` scope).
5. Persist the **refresh token** (+ client id) via the credstore.

At runtime the daemon mints short-lived access tokens from the stored refresh token before each WebSocket dial, persisting each rotated refresh token. There is no `client_credentials` grant and no long-lived API key — the token carries the user's identity.

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

### `no credentials for <server>`

The daemon couldn't find credentials for the configured server URL. Either:

- Run `shellwatch-agent login --server <server>` (browser passkey login), or
- Pass `--api-key` / set `SHELLWATCH_API_KEY` to a bearer token with the `agent` scope.

If you ran `login` against a different server URL than the daemon is using, the credentials won't match. Run `login` again for the URL the daemon expects.

## Tests

```bash
go test ./...
```

## License

[MIT](./LICENSE) — the agent runs on end-user machines, so we keep it
permissive and frictionless. The ShellWatch server and client at the
repository root ship under [FSL-1.1-Apache-2.0](../LICENSE) instead.
