# SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
# Throwaway OpenSSH target for the Go rewrite Phase 0 spike (#232 item 4).
# Trusts the spike user CA (mounted at /etc/ssh/user_ca.pub) and accepts
# webauthn-sk-* algorithms — see sshd_config.
#
# edge, not a stable tag: webauthn-sk-* pubkey auth needs OpenSSH >= 10.3
# (alpine 3.22 ships 10.0, which rejects the algorithm name outright —
# "Bad key types"). Digest-pinned so the spike stays reproducible while on
# the moving tag (this digest = OpenSSH 10.3_p1); bump the digest if edge
# needs a security rebuild, and switch to the next stable alpine that
# carries 10.3+.
FROM alpine:edge@sha256:9a341ff2287c54b86425cbee0141114d811ae69d88a36019087be6d896cef241

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
