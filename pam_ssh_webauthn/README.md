# pam_ssh_webauthn

A PAM module that authenticates users via WebAuthn passkeys through a forwarded SSH agent. It verifies `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signatures — the key type produced when a FIDO2/WebAuthn authenticator is used as an SSH key with a non-`ssh:` relying party ID.

This module is **standalone** and has **no dependency on ShellWatch** or any other specific SSH agent implementation. It works with any SSH agent that:

1. Holds keys of type `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`
2. Produces WebAuthn-format signatures (with `origin`, `clientDataJSON`, and `extensions` fields) in response to `SSH_AGENTC_SIGN_REQUEST`

## What it does

When a user runs `sudo` (or any PAM-authenticated command), the module:

1. Reads authorized public keys from a configured file (default: `/etc/security/authorized_keys`)
2. Connects to the SSH agent at `$SSH_AUTH_SOCK`
3. Lists agent identities, filters for `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` keys
4. Matches agent keys against authorized keys by raw key blob comparison
5. Generates a 32-byte random challenge
6. Sends `SSH_AGENTC_SIGN_REQUEST` to the agent
7. Receives the signature with WebAuthn fields (origin, clientDataJSON, extensions)
8. Validates the challenge is base64url-encoded in `clientDataJSON`
9. Constructs `signed_data = SHA256(application) || flags || counter || SHA256(clientDataJSON)`
10. Verifies the ECDSA P-256 signature over `signed_data`
11. Returns `PAM_SUCCESS` or `PAM_AUTH_ERR`

## What it does NOT do

- Standard SSH key types (RSA, Ed25519, ECDSA) — use [pam-ssh-agent](https://github.com/nresare/pam-ssh-agent) for those
- Standard FIDO2 SK keys (`sk-ecdsa-sha2-nistp256@openssh.com` with `application=ssh:`)
- Ed25519 SK keys
- SSH certificates
- `authorized_keys_command` execution

Non-webauthn keys in the authorized keys file are silently ignored.

## Trust model

- **Trusted**: authenticator hardware, browser origin check, this PAM verifier
- **Transport only**: the SSH agent forwarder (e.g. ShellWatch, or any agent forwarding mechanism) cannot forge signatures — it can only deny or delay them
- **Verified on target**: ECDSA P-256 signature over a fresh challenge, checked against the public key in the authorized keys file

## Build

Requires Rust 1.70+ and PAM development headers.

```bash
# Install PAM headers (Linux)
sudo apt install libpam0g-dev    # Debian/Ubuntu
sudo dnf install pam-devel       # Fedora/RHEL

# Build the shared library
cargo build --release

# The PAM module is at:
# target/release/libpam_ssh_webauthn.so  (Linux)
# target/release/libpam_ssh_webauthn.dylib  (macOS)
```

### FIPS / OpenSSL backend

By default, ECDSA verification uses the pure Rust `p256` crate. For environments requiring OpenSSL (e.g. FIPS compliance):

```bash
cargo build --release --features native-crypto
```

This requires OpenSSL development headers (`libssl-dev` / `openssl-devel`).

## Setup on target machine

### 1. Install the PAM module

```bash
# Linux
sudo cp target/release/libpam_ssh_webauthn.so /usr/lib/x86_64-linux-gnu/security/pam_ssh_webauthn.so

# macOS (for testing)
sudo cp target/release/libpam_ssh_webauthn.dylib /usr/lib/pam/pam_ssh_webauthn.so
```

### 2. Add authorized keys

Create `/etc/security/authorized_keys` with WebAuthn public keys:

```
webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAA... user-comment
```

The key must be the exact key blob the SSH agent presents — same EC point and same application/relying party ID. Standard SSH keys and other key types in this file are ignored.

### 3. Configure PAM

Add to `/etc/pam.d/sudo` (before other auth lines):

```
auth sufficient pam_ssh_webauthn.so
```

Or with a custom key file path:

```
auth sufficient pam_ssh_webauthn.so file=/path/to/authorized_keys
```

To override the agent socket path (instead of `$SSH_AUTH_SOCK`):

```
auth sufficient pam_ssh_webauthn.so socket=/path/to/agent.sock
```

### 4. Preserve SSH_AUTH_SOCK for sudo

```bash
# /etc/sudoers.d/ssh-auth-sock
Defaults env_keep += "SSH_AUTH_SOCK"
```

## Testing locally

The included `authenticator` example runs the full authentication flow without PAM:

```bash
# Set up the agent socket (from your SSH agent forwarder)
export SSH_AUTH_SOCK=/path/to/agent.sock

# Run against a key file
cargo run --example authenticator -- /path/to/authorized_keys
```

The `list_keys` example shows decoded key blobs from the agent:

```bash
export SSH_AUTH_SOCK=/path/to/agent.sock
cargo run --example list_keys
```

## Wire formats

### Key blob (`webauthn-sk-ecdsa-sha2-nistp256@openssh.com`)

```
string  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
string  "nistp256"
string  ec_point        (65 bytes: 0x04 || x || y, uncompressed P-256)
string  application     (relying party ID, e.g. "localhost", "example.com")
```

### Signature blob (WebAuthn variant)

```
string  algorithm       ("sk-ecdsa-sha2-nistp256@openssh.com" or "webauthn-...")
string  ecdsa_signature (mpint R || mpint S)
byte    flags
uint32  counter
string  origin          (WebAuthn origin URL)
string  clientDataJSON  (contains base64url-encoded challenge)
string  extensions      (CBOR, typically empty)
```

### Verification

```
signed_data = SHA256(application) || flags || counter || extensions || SHA256(clientDataJSON)
```

ECDSA P-256 signature is verified over `signed_data` using the public key from the authorized keys file.

### Validation checks

The following checks are performed, matching OpenSSH's `webauthn_check_prepare_hash`:

- **Algorithm**: Must be `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com`
- **User Presence (UP)**: Flag bit 0x01 must be set
- **Attested Credential Data (AD)**: Flag bit 0x40 must NOT be set (this is an assertion, not a registration)
- **Extension Data (ED)**: Flag bit 0x80 must be consistent with extensions presence
- **Origin**: Must not contain quote characters (prevents JSON injection); must match between signature blob and clientDataJSON
- **clientDataJSON type**: Must be `"webauthn.get"`
- **clientDataJSON challenge**: Must match the base64url-encoded challenge sent to the agent
- **clientDataJSON origin**: Must match the origin from the signature blob
- **Trailing data**: Rejected — no extra bytes allowed after the extensions field

### Limitations

- **No counter/replay protection**: The WebAuthn counter is integrity-protected (included in signed_data) but not checked for monotonic increase. Counter validation requires persistent state (tracking the last-seen counter per key), which is not appropriate for a stateless PAM module. This means a captured signature cannot be replayed (the challenge is fresh each time), but a cloned authenticator with a reset counter would not be detected.
- **No User Verification (UV) enforcement**: The UV flag is not required, as some authenticators may not support it. UP (User Presence) is always required.

## Logging

Logs to syslog facility `AUTH` as `pam_ssh_webauthn`. Set log level via PAM or syslog configuration.

## Troubleshooting

**`SSH_AUTH_SOCK not set`** — The module reads `$SSH_AUTH_SOCK` from the environment. For sudo, this must be preserved:

```bash
# /etc/sudoers.d/ssh-auth-sock
Defaults env_keep += "SSH_AUTH_SOCK"
```

**Agent timeout** — The module waits up to 60 seconds for the agent to respond. This is generous because the sign request may require user interaction (e.g. tapping a passkey in the browser). If the agent is unresponsive, authentication fails with a timeout error after 60s.

**No matching key** — Key matching is done by raw blob comparison, which includes the application/relying party ID. If the key in `authorized_keys` was generated with a different RP ID than the one the agent holds, they will not match even if the underlying EC key material is identical. Use the `list_keys` example to inspect the agent's key blobs:

```bash
SSH_AUTH_SOCK=/path/to/agent.sock cargo run --example list_keys
```

**Silent failures** — Enable debug logging to see detailed matching and verification steps. The module logs to syslog facility `AUTH`.
