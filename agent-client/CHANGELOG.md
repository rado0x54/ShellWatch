# Changelog

## v0.0.1 (2026-04-07)

- feat: SSH agent proxy endpoint + Go thin client (#22) (6f029cc)
- fix: handle SSH_AGENTC_EXTENSION in Go proxy, exclude passkeys from agent (#36) (20ca20b)
- fix: address review feedback — per-connection WS, agent scope, socket path (35efad1)
- docs: add agent-client README and agent proxy section to main README (8263959)
- feat: support passkeys through agent proxy (requires OpenSSH 10.3+) (d741211)
- docs: add troubleshooting section for pre-10.3 passkey errors (0e6b1ca)
