<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<!--
  Walks a user through the two-line server-side setup for ShellWatch passkey
  auth. Reused by:
    - the "Add Your Own Endpoint" wizard (passes the freshly-registered passkey
      so the authorized_keys command is fully copy-pastable)
    - the /settings/setup help tab (no passkey context; renders an instructional
      placeholder + a link to /settings/passkeys)
-->
<script lang="ts">
  import Wordmark from "./Wordmark.svelte";

  interface Props {
    /**
     * Optional passkey to inline into the second copy-block. When omitted, the
     * second block shows a placeholder and a hint to grab the entry from
     * Settings → Passkeys.
     */
    passkey?: { authorizedKeysEntry: string | null; label: string } | null;
    /** Account name used to scope the authorized_keys comment. Defaults to "user". */
    accountName?: string;
  }

  let { passkey = null, accountName = "user" }: Props = $props();

  // Single source for the sshd line — referenced from both the visible code
  // block and the clipboard handler so they can't drift. Mirrors the value
  // computed server-side in src/webauthn/ssh-key-format.ts; if that changes
  // (additional algorithms, multi-line config), surface it through the
  // register response and consume it here instead.
  const SSHD_CONFIG_LINE = "PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com";
  const SSHD_CONFIG_ONE_LINER = `echo '${SSHD_CONFIG_LINE}' | sudo tee -a /etc/ssh/sshd_config`;

  function sshComment(label: string): string {
    const sanitize = (s: string) =>
      s
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "_")
        .replace(/_+/g, "_")
        .replace(/^_|_$/g, "");
    const host = sanitize(window.location.hostname);
    const name = sanitize(accountName.trim() || "user");
    const key = sanitize(label);
    return `${host}-${name}-${key}`;
  }

  const sshLine = $derived(
    passkey?.authorizedKeysEntry
      ? `${passkey.authorizedKeysEntry} ${sshComment(passkey.label)}`
      : null,
  );

  const sshOneLiner = $derived(sshLine ? `echo '${sshLine}' >> ~/.ssh/authorized_keys` : null);

  async function copyToClipboard(text: string, btn: HTMLButtonElement) {
    const original = btn.innerHTML;
    try {
      await navigator.clipboard.writeText(text);
      btn.innerHTML = "&#10003; Copied";
    } catch {
      // Insecure context (HTTP non-localhost) or denied permission — surface
      // the failure instead of flashing a false-positive "Copied" state.
      btn.innerHTML = "Copy failed";
    }
    setTimeout(() => {
      btn.innerHTML = original;
    }, 1500);
  }
</script>

<p class="description">
  Two one-time steps on each server you want to reach. Requires
  <strong>OpenSSH 8.4+</strong>.
</p>

<div class="code-block">
  <span class="code-label"
    >1. Enable WebAuthn keys in <code>/etc/ssh/sshd_config</code> (reload sshd after)</span
  >
  <code class="code-content">{SSHD_CONFIG_ONE_LINER}</code>
  <button
    type="button"
    class="btn-copy"
    onclick={(e) => copyToClipboard(SSHD_CONFIG_ONE_LINER, e.currentTarget as HTMLButtonElement)}
    >Copy</button
  >
</div>

{#if sshOneLiner && sshLine}
  <div class="code-block">
    <span class="code-label">2. Add this passkey to <code>~/.ssh/authorized_keys</code></span>
    <code class="code-content">{sshOneLiner}</code>
    <button
      type="button"
      class="btn-copy"
      onclick={(e) => copyToClipboard(sshOneLiner!, e.currentTarget as HTMLButtonElement)}
      >Copy</button
    >
  </div>
{:else if passkey}
  <p class="hint">
    This authenticator does not expose an SSH-compatible public key. You can still use it for <Wordmark
    /> login. To enable SSH, register a different passkey from Settings.
  </p>
{:else}
  <div class="code-block">
    <span class="code-label">2. Add a passkey to <code>~/.ssh/authorized_keys</code> (example)</span
    >
    <code class="code-content placeholder">
      echo 'webauthn-sk-ecdsa-sha2-nistp256@openssh.com
      AAAAK3dlYmF1dGhuLXNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBExample…=
      example_com-alice-yubikey5' &gt;&gt; ~/.ssh/authorized_keys
    </code>
  </div>
  <p class="hint">
    Replace the key body and comment with your own — copy the exact one-liner for a specific passkey
    from <strong>Settings → Passkeys</strong>.
  </p>
{/if}

<style>
  .description,
  .hint {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-bottom: 0.75rem;
    line-height: 1.55;
  }

  .hint {
    font-size: 0.78rem;
  }

  .code-block {
    position: relative;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    margin-bottom: 0.75rem;
    text-align: left;
  }

  .code-label {
    display: block;
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin-bottom: 0.35rem;
  }

  .code-content {
    display: block;
    font-size: 0.75rem;
    word-break: break-all;
    padding-right: 3.5rem; /* leave room for the absolute Copy button */
  }

  .code-content.placeholder {
    color: var(--text-muted);
    font-style: italic;
  }

  .btn-copy {
    position: absolute;
    top: 0.4rem;
    right: 0.4rem;
    padding: 0.25rem 0.5rem;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.7rem;
    cursor: pointer;
  }

  .btn-copy:hover {
    background: var(--border);
  }

  @media (max-width: 640px) {
    .code-content {
      font-size: 0.7rem;
    }
  }
</style>
