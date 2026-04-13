# Changelog

## v0.0.2 (2026-04-13)

- fix: iterate matching keys instead of giving up after the first failed sign ([#91](https://github.com/rado0x54/ShellWatch/issues/91)) ([#92](https://github.com/rado0x54/ShellWatch/pull/92))
- fix: distinguish protocol refusal (`SSH_AGENT_FAILURE`) from transport errors so "agent is down" surfaces instead of masquerading as "no key matched" ([#92](https://github.com/rado0x54/ShellWatch/pull/92))

## v0.0.1 (2026-04-10)

- feat: dedicated pam_ssh_webauthn module ([#65](https://github.com/rado0x54/ShellWatch/pull/65)) ([#66](https://github.com/rado0x54/ShellWatch/pull/66))
