<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->

# Throwaway sshd host keys (e2e only)

Committed on purpose so the e2e targets have a **stable host-key fingerprint**
across rebuilds (a future scenario can assert on it; the Node server has no
host-key pinning today). They protect nothing: the containers only ever listen
on `127.0.0.1` during a test run. **Never reuse these keys anywhere.**

Regenerate with:

```bash
ssh-keygen -t ed25519 -N "" -C shellwatch-e2e-throwaway-hostkey -f ssh_host_ed25519_key
ssh-keygen -t ecdsa -b 256 -N "" -C shellwatch-e2e-throwaway-hostkey -f ssh_host_ecdsa_key
```
