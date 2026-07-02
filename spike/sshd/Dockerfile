# SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
# Throwaway OpenSSH target for the Go rewrite Phase 0 spike (#232 item 4).
# Trusts the spike user CA (mounted at /etc/ssh/user_ca.pub) and accepts
# webauthn-sk-* algorithms — see sshd_config.
#
# edge, not a stable tag: webauthn-sk-* pubkey auth needs OpenSSH >= 10.3
# (alpine 3.22 ships 10.0, which rejects the algorithm name outright —
# "Bad key types"). Pin to the next stable alpine that carries 10.3+.
FROM alpine:edge

RUN apk add --no-cache openssh-server \
  && adduser -D -s /bin/sh spike \
  # Alpine creates the account locked ("!" in shadow); sshd refuses locked
  # accounts. "*" = no password, but the account is usable with pubkey auth.
  && sed -i 's/^spike:!/spike:*/' /etc/shadow

COPY sshd_config /etc/ssh/sshd_config

# Host keys are generated at first start (ssh-keygen -A) so each spike run
# gets fresh throwaway keys; -e logs to stderr for `docker compose logs`.
EXPOSE 22
CMD ["sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
