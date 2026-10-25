#!/bin/sh
# SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
# e2e sshd entrypoint (#244): install the committed throwaway host keys (mounted
# read-only at /hostkeys — sshd insists on 0600, so copy rather than use in
# place), prepare the users' ~/.ssh so the harness can drop authorized_keys in
# via `docker compose exec`, optionally enable the webauthn-sk algorithm, then
# run sshd in the foreground logging to stderr (→ `docker compose logs`).
set -eu

mkdir -p /etc/ssh/sshd_config.d /run/sshd

for key in /hostkeys/ssh_host_*_key; do
  cp "$key" /etc/ssh/
  chmod 600 "/etc/ssh/$(basename "$key")"
done
for pub in /hostkeys/ssh_host_*_key.pub; do
  cp "$pub" /etc/ssh/
done

if [ "${SSHD_WEBAUTHN_SK:-0}" = "1" ]; then
  # Same directive ShellWatch shows users for their own servers
  # (the OpenSSH authorized_keys/sshd_config line for a webauthn-sk key).
  echo 'PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com' \
    > /etc/ssh/sshd_config.d/10-webauthn-sk.conf
fi

# OpenSSH >= 9.8 penalises a source IP after failed authentications
# (PerSourcePenalties, on by default). Every ShellWatch connection offers the
# admin file key (ed25519) before the passkey, and sshd rejects that probe for
# the passkey-only user — harmless on its own, but back-to-back scenarios
# accumulate enough "failed authentication" penalties that sshd starts dropping
# the harness's connections mid-suite (flaky passkey-signing). Disable it where
# the directive exists (the OpenSSH 10.3 modern image); the debian-stable image
# (9.2) neither knows the directive nor penalises, so the probe skips it there.
if /usr/sbin/sshd -T 2>/dev/null | grep -qi '^persourcepenalties'; then
  echo 'PerSourcePenalties no' > /etc/ssh/sshd_config.d/20-no-penalties.conf
fi

for u in filekey passkey; do
  install -d -m 700 -o "$u" -g "$u" "/home/$u/.ssh"
done

/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
