## v1.0.0 (2026-05-03)

- chore: adopt FSL-1.1-Apache-2.0 license ([#192](https://github.com/rado0x54/ShellWatch/pull/192))

## v0.1.0 (2026-05-01)

- feat(agent): Windows support — named-pipe listener + windows build matrix ([#175](https://github.com/rado0x54/ShellWatch/pull/175)) ([#177](https://github.com/rado0x54/ShellWatch/pull/177))
- docs: surface the homebrew tap as the primary install path ([#176](https://github.com/rado0x54/ShellWatch/pull/176))
- feat(agent): shellwatch-agent login/logout via loopback PKCE + credstore ([#171](https://github.com/rado0x54/ShellWatch/pull/171)) ([#173](https://github.com/rado0x54/ShellWatch/pull/173))
- feat(agent): default --server, ws keepalive + reconnect, daemon docs ([#157](https://github.com/rado0x54/ShellWatch/pull/157))
- chore(release): open changelog PR instead of pushing directly to main ([#152](https://github.com/rado0x54/ShellWatch/pull/152))
- feat: enrich agent-proxy sign context with API key label and client metadata ([#69](https://github.com/rado0x54/ShellWatch/pull/69))
- fix: use clickable markdown links in changelogs
- fix: changelog short links, agent path filtering, and develop sync

## v0.0.1 (2026-04-07)

- feat: SSH agent proxy endpoint + Go thin client ([#22](https://github.com/rado0x54/ShellWatch/pull/22)) (6f029cc)
- fix: handle SSH_AGENTC_EXTENSION in Go proxy, exclude passkeys from agent ([#36](https://github.com/rado0x54/ShellWatch/pull/36)) (20ca20b)
- fix: address review feedback — per-connection WS, agent scope, socket path (35efad1)
- docs: add agent-client README and agent proxy section to main README (8263959)
- feat: support passkeys through agent proxy (requires OpenSSH 10.3+) (d741211)
- docs: add troubleshooting section for pre-10.3 passkey errors (0e6b1ca)
