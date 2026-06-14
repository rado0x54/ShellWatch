## Unreleased

### ⚠️ Breaking: Ory Hydra is now the OAuth2/OIDC authority (#217)

ShellWatch no longer ships its own OAuth shim or API keys. **Ory Hydra (backed by
a file SQLite store, in the same folder as ShellWatch's own DB) is now a hard
runtime dependency** and the single OAuth2/OIDC authority
for all delegated access. Every client — the web UI, MCP clients, and the Go
agent-client — uses the **same flow**: mediated Dynamic Client Registration +
`authorization_code` + PKCE, with the user logging in via a passkey and
consenting. The access token carries the identity (`sub` = account); an OAuth
client is never bound to an account. ShellWatch is Hydra's passkey-gated login +
consent provider; authentication stays passkey-only. SSH signing /
`webauthn-sk-*` keys are untouched.

**This is a hard cutover — there is no migration of existing credentials:**

- **Existing API keys stop working.** The `api_keys` table is dropped (no new
  tables are added).
- **Web users** sign in again with their passkey. The web UI is now a public
  PKCE client holding its token in the browser (access token in memory, rotating
  refresh token); `/api/*` + `/ws` authenticate via Bearer (a `ui` scope).
- **MCP clients** (Claude.ai, MCP Inspector, …) re-onboard automatically via DCR
  → passkey consent.
- **Agent clients**: run `shellwatch-agent login` (browser passkey login). The
  old API-key / `client_credentials` paths and Settings → OAuth Clients are
  gone.
- **Headless/CI agents are unsupported** until a Device Authorization Grant
  follow-up — every agent now does an interactive browser login.

**Upgrade steps:**

1. Stand up Hydra (a sibling stack, file SQLite — no separate DB server):
   `pnpm hydra:migrate` (creates the schema), then
   `docker compose --env-file .env.hydra up -d hydra`.
2. Add the `hydra:` section to `config.yaml` (see `config.sample.yaml`): public
   issuer URL, admin URL, and the SPA `clientId`.
3. Keep Hydra's **admin port (`:4445`) off the public internet** — only the
   public port (`:4444`) is exposed to clients; configure its CORS to allow the
   web-UI origin.
4. Re-authenticate: web users via passkey; agents via `shellwatch-agent login`.

See [docs/deployment.md](./docs/deployment.md#ory-hydra-oauth-authority) for the
full deployment + local-dev story.

## v1.0.2 (2026-05-18)

## What's Changed

- chore: misc UX polish across sidebar, observer and onboarding by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/212
- feat: per-endpoint SSH agent forwarding toggle by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/213
- feat: virtual demo endpoints + Settings UX overhaul (closes #211) by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/214
- Preprod Release by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/215

**Full Changelog**: https://github.com/rado0x54/ShellWatch/compare/v1.0.1...v1.0.2

## v1.0.1 (2026-05-05)

## What's Changed

- ci: drop develop-FF gate from release dispatches; require main by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/200
- Preprod Release by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/201
- chore: update agent CHANGELOG.md for agent/v1.0.0 by @github-actions[bot] in https://github.com/rado0x54/ShellWatch/pull/202
- docs: align README and docs/ with current code by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/203
- docs: refactor README — logo, tagline, requirements, dev/prod flow by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/204
- chore: self-host Geist fonts; drop Google Fonts dependency by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/206
- ci: bump homebrew-tap formula on agent release by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/205
- Preprod Release by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/207

**Full Changelog**: https://github.com/rado0x54/ShellWatch/compare/v1.0.0...v1.0.1

## v1.0.0 (2026-05-03)

## What's Changed

- chore: update agent CHANGELOG.md for agent/v0.1.0 by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/179
- fix(ui): icon-only sidebar session actions by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/183
- feat(audit): session-lifecycle audit log + UI by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/187
- chore(terminal): require CloseReason on TerminalManager.close() by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/188
- feat(audit): persist signing requests and surface in UI (#186) by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/190
- chore: adopt FSL-1.1-Apache-2.0 license by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/192
- fix(licenses): cover all cbor-extract platform variants by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/196
- chore: scrub internal references for public release by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/195
- docs: consolidate agent instructions into CLAUDE.md and refresh positioning by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/198
- Release PR by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/197

## New Contributors

- @github-actions[bot] made their first contribution in https://github.com/rado0x54/ShellWatch/pull/180

**Full Changelog**: https://github.com/rado0x54/ShellWatch/compare/v0.1.0...v1.0.0

## v0.1.0 (2026-05-01)

## What's Changed

- chore(release): open changelog PR instead of pushing directly to main by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/152
- chore: remove pam_ssh_webauthn module by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/154
- chore(release): workflow_dispatch + PR-based CHANGELOG flow by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/155
- feat(agent): default --server, ws keepalive + reconnect, daemon docs by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/157
- feat(client): add Details button to sign-request toast by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/158
- feat(passkey): invite flow for enrolling passkeys on a second device (#101) by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/160
- feat(webauthn): step-up assertion for passkey add/revoke/confirm by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/163
- fix(settings): mobile tabs unusable — swap for native dropdown + extract SectionTabs by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/165
- chore(mcp): expand sudo guidance — no chaining, allow time for OOB PAM by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/167
- chore(client): add type="button" to all <button> elements + lint rule by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/168
- fix: anchor keys/ gitignore rule to repo root by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/169
- fix(client): replace window.confirm/alert with in-app modals and toasts by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/170
- feat(oauth): accept scope + resource params, support agent-scoped keys (#171) by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/172
- feat(agent): shellwatch-agent login/logout via loopback PKCE + credstore (#171) by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/173
- feat(oauth): scope-aware new-key placeholder (agent-only -> shellwatch-agent) by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/174
- docs: surface the homebrew tap as the primary install path by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/176
- feat(agent): Windows support — named-pipe listener + windows build matrix (#175) by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/177
- Preprod Release by @rado0x54 in https://github.com/rado0x54/ShellWatch/pull/178

**Full Changelog**: https://github.com/rado0x54/ShellWatch/compare/v0.0.2...v0.1.0

## v0.0.2 (2026-04-27)

## What's Changed

- feat: support PUID/PGID env vars for Docker volume permissions by @rado0x54 in [#60](https://github.com/rado0x54/ShellWatch/pull/60)
- feat: export seed config from admin UI (#58) by @rado0x54 in [#61](https://github.com/rado0x54/ShellWatch/pull/61)
- feat: SSH agent forwarding in hosted sessions (#63) by @rado0x54 in [#64](https://github.com/rado0x54/ShellWatch/pull/64)
- feat: dedicated pam_ssh_webauthn module (#65) by @rado0x54 in [#66](https://github.com/rado0x54/ShellWatch/pull/66)
- feat: prebuilt PAM module binaries in release workflow by @rado0x54 in [#67](https://github.com/rado0x54/ShellWatch/pull/67)
- chore: construct test configs via Zod defaults (#42) by @rado0x54 in [#68](https://github.com/rado0x54/ShellWatch/pull/68)
- feat: PendingAction system for unified signing notifications (#38) by @rado0x54 in [#70](https://github.com/rado0x54/ShellWatch/pull/70)
- feat: human-in-the-loop approval for file-based SSH key signing (#71) by @rado0x54 in [#72](https://github.com/rado0x54/ShellWatch/pull/72)
- feat: surface errors to UI via toast notifications by @rado0x54 in [#74](https://github.com/rado0x54/ShellWatch/pull/74)
- feat: PWA support with Web Push notifications for sign requests by @rado0x54 in [#76](https://github.com/rado0x54/ShellWatch/pull/76)
- fix: suppress push notification when a ShellWatch tab is visible by @rado0x54 in [#77](https://github.com/rado0x54/ShellWatch/pull/77)
- feat: restructure SignRequestContext taxonomy and enrich /sign/:id (#69) by @rado0x54 in [#78](https://github.com/rado0x54/ShellWatch/pull/78)
- feat: enrich agent-proxy sign context with API key label and client metadata (#69) by @rado0x54 in [#80](https://github.com/rado0x54/ShellWatch/pull/80)
- feat: agent-forwarding parent-session preview with xterm.js snapshot (#69) by @rado0x54 in [#81](https://github.com/rado0x54/ShellWatch/pull/81)
- fix: make forwardingOnFileKeySignRequest required on ForwardingAgent (#79) by @rado0x54 in [#83](https://github.com/rado0x54/ShellWatch/pull/83)
- feat: MCP clientInfo capture + required reason on session creation (#82, #34) by @rado0x54 in [#84](https://github.com/rado0x54/ShellWatch/pull/84)
- fix: honor reverse-proxy headers via server.trustProxy (#85) by @rado0x54 in [#86](https://github.com/rado0x54/ShellWatch/pull/86)
- feat: terminal:attach full-buffer replay with resume-by-offset (#87) by @rado0x54 in [#90](https://github.com/rado0x54/ShellWatch/pull/90)
- fix: don't abort SSH client when a sign request is denied (#91) by @rado0x54 in [#92](https://github.com/rado0x54/ShellWatch/pull/92)
- fix: return 404 for stale MCP session IDs so clients reinitialize by @rado0x54 in [#93](https://github.com/rado0x54/ShellWatch/pull/93)
- feat: allow selecting scopes when creating API keys in the UI by @rado0x54 in [#94](https://github.com/rado0x54/ShellWatch/pull/94)
- chore: wire svelte-check into CI + husky, fix pre-existing errors by @rado0x54 in [#96](https://github.com/rado0x54/ShellWatch/pull/96)
- feat: enforce userVerification by default, per-endpoint override + docs by @rado0x54 in [#99](https://github.com/rado0x54/ShellWatch/pull/99)
- feat: optional endpoint description (MCP-surfaced) + shared Modal component by @rado0x54 in [#102](https://github.com/rado0x54/ShellWatch/pull/102)
- fix: SSH fingerprints match OpenSSH encoding (ssh-add -l / ssh-keygen -lf) (#105) by @rado0x54 in [#106](https://github.com/rado0x54/ShellWatch/pull/106)
- feat(oauth-mini): minimal OAuth 2.1 DCR shim for MCP clients by @rado0x54 in [#109](https://github.com/rado0x54/ShellWatch/pull/109)
- feat(design): Obsidian Command — full client + OAuth + settings refactor by @rado0x54 in [#110](https://github.com/rado0x54/ShellWatch/pull/110)
- fix(client): absolute path for runtime config.js script by @rado0x54 in [#112](https://github.com/rado0x54/ShellWatch/pull/112)
- fix(auth-gate): exempt public static assets from session gate by @rado0x54 in [#113](https://github.com/rado0x54/ShellWatch/pull/113)
- fix(client): force full replay on fresh terminal mount after observer mode by @rado0x54 in [#114](https://github.com/rado0x54/ShellWatch/pull/114)
- chore(docker): run as non-root via USER directive, drop PUID/PGID entrypoint by @rado0x54 in [#115](https://github.com/rado0x54/ShellWatch/pull/115)
- fix(agent-proxy): translate denied sign requests to failureReply by @rado0x54 in [#117](https://github.com/rado0x54/ShellWatch/pull/117)
- chore(webauthn): restrict passkey registration to ES256 only by @rado0x54 in [#118](https://github.com/rado0x54/ShellWatch/pull/118)
- chore: setup UX polish (modals, inputs, register flow, cookieSecret docs) by @rado0x54 in [#119](https://github.com/rado0x54/ShellWatch/pull/119)
- fix(ws): scope session list and message handlers by account by @rado0x54 in [#121](https://github.com/rado0x54/ShellWatch/pull/121)
- refactor(auth): tighten accountId types on /mcp and WsExtension by @rado0x54 in [#124](https://github.com/rado0x54/ShellWatch/pull/124)
- fix(ws): replace global uiCreatedSessions with per-client control state (#123) by @rado0x54 in [#126](https://github.com/rado0x54/ShellWatch/pull/126)
- refactor(auth): tighten accountId, unify bearer-gate, reorganize webauthn routes (#125) by @rado0x54 in [#127](https://github.com/rado0x54/ShellWatch/pull/127)
- fix(mcp): prevent cross-account MCP session hijack via mcp-session-id (#128) by @rado0x54 in [#133](https://github.com/rado0x54/ShellWatch/pull/133)
- fix(mcp): scope AgentSession to caller account, fix cross-tenant endpoint disclosure (#129) by @rado0x54 in [#135](https://github.com/rado0x54/ShellWatch/pull/135)
- fix(mcp): scope AgentSession.createSession to caller account (#130) by @rado0x54 in [#137](https://github.com/rado0x54/ShellWatch/pull/137)
- fix(push): SSRF allowlist + account-scoped subscription ownership (#131) by @rado0x54 in [#139](https://github.com/rado0x54/ShellWatch/pull/139)
- refactor(db): tighten repo interfaces — scoped is the default, no unused unscoped reads (#136) by @rado0x54 in [#140](https://github.com/rado0x54/ShellWatch/pull/140)
- fix: tear down terminals + MCP transports on account delete (#122, #134) by @rado0x54 in [#141](https://github.com/rado0x54/ShellWatch/pull/141)
- feat(onboarding): SSH server setup, MCP intro, notifications, advanced topics (#142) by @rado0x54 in [#143](https://github.com/rado0x54/ShellWatch/pull/143)
- feat(version): expose build SHA + ref via /api/version and Settings → General (#138) by @rado0x54 in [#146](https://github.com/rado0x54/ShellWatch/pull/146)
- chore: consolidate fastify FastifyRequest augmentations (#132) by @rado0x54 in [#148](https://github.com/rado0x54/ShellWatch/pull/148)
- fix(release): correct crane mutate flag (--env not --set-env) by @rado0x54 in [#149](https://github.com/rado0x54/ShellWatch/pull/149)

**Full Changelog**: https://github.com/rado0x54/ShellWatch/compare/v0.0.1...v0.0.2

## v0.0.1 (2026-04-07)

## What's Changed

- feat: migrate frontend to SvelteKit with responsive layout and routing by @rado0x54 in [#24](https://github.com/rado0x54/ShellWatch/pull/24)
- feat: account model with onboarding flow by @rado0x54 in [#27](https://github.com/rado0x54/ShellWatch/pull/27)
- feat: per-account scoping, registration flow, admin management by @rado0x54 in [#29](https://github.com/rado0x54/ShellWatch/pull/29)
- refactor: unify key model — eliminate dual passkey rows (#28) by @rado0x54 in [#30](https://github.com/rado0x54/ShellWatch/pull/30)
- feat: automatic SSH key negotiation (#31) by @rado0x54 in [#32](https://github.com/rado0x54/ShellWatch/pull/32)
- fix: require security.rpId and trustedWebauthnOrigins in config by @rado0x54 in [#33](https://github.com/rado0x54/ShellWatch/pull/33)
- SSH agent proxy endpoint + Go thin client by @rado0x54 in [#37](https://github.com/rado0x54/ShellWatch/pull/37)
- feat: support passkeys through agent proxy by @rado0x54 in [#39](https://github.com/rado0x54/ShellWatch/pull/39)
- refactor: extract god files into focused modules by @rado0x54 in [#45](https://github.com/rado0x54/ShellWatch/pull/45)
- fix: terminal not switching when clicking different sessions by @rado0x54 in [#46](https://github.com/rado0x54/ShellWatch/pull/46)
- feat: AAGUID-based passkey naming with server-side lookup by @rado0x54 in [#48](https://github.com/rado0x54/ShellWatch/pull/48)
- fix: onboarding adopts seeded admin instead of creating duplicate by @rado0x54 in [#49](https://github.com/rado0x54/ShellWatch/pull/49)
- ci: add GitHub Actions CI workflow by @rado0x54 in [#50](https://github.com/rado0x54/ShellWatch/pull/50)
- feat: rate limiting + registration toggle by @rado0x54 in [#52](https://github.com/rado0x54/ShellWatch/pull/52)
- feat: hide registration UI when self-registration is disabled by @rado0x54 in [#54](https://github.com/rado0x54/ShellWatch/pull/54)
- fix: remove basePath functionality (#53) by @rado0x54 in [#55](https://github.com/rado0x54/ShellWatch/pull/55)
- feat: release pipeline, Dockerfile, and deployment docs by @rado0x54 in [#57](https://github.com/rado0x54/ShellWatch/pull/57)

## New Contributors

- @rado0x54 made their first contribution in [#24](https://github.com/rado0x54/ShellWatch/pull/24)

**Full Changelog**: https://github.com/rado0x54/ShellWatch/commits/v0.0.1
