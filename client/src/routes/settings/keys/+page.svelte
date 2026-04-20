<script lang="ts">
  import { onMount } from "svelte";
  import { account } from "$lib/stores/account.js";
  import { fetchSshKeys, sshKeys } from "$lib/stores/keys.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import {
    credentials,
    fetchCredentials,
    renamePasskey,
    startPasskeyRegistration,
  } from "$lib/stores/webauthn.js";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";

  let revoking = $state(false);
  let registering = $state(false);
  let editingId = $state<string | null>(null);
  let editLabel = $state("");

  onMount(() => {
    fetchCredentials();
    fetchSshKeys();
  });

  function sanitizeSegment(s: string): string {
    return s
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "_")
      .replace(/_+/g, "_")
      .replace(/^_|_$/g, "");
  }

  function sshComment(label: string): string {
    const host = sanitizeSegment(window.location.hostname);
    const name = sanitizeSegment($account?.name ?? "unknown");
    const key = sanitizeSegment(label);
    return `${host}-${name}-${key}`;
  }

  function copyKey(key: string, btn: HTMLButtonElement) {
    navigator.clipboard.writeText(key);
    const original = btn.innerHTML;
    btn.innerHTML = "&#10003;";
    setTimeout(() => {
      btn.innerHTML = original;
    }, 1500);
  }

  async function handleRevoke(id: string) {
    // TODO: use basePath store instead of window.__BASE_PATH__ (applies to this fn and handleRevokeFileKey)
    const activeCount = $credentials.filter((c) => !c.revoked).length;
    if (activeCount <= 1) {
      // Client-side guard for UX; also enforced server-side in the revoke endpoint
      toastError("Cannot revoke the last active passkey.");
      return;
    }
    if (!confirm("Revoke this passkey? This is permanent and cannot be undone.")) return;
    revoking = true;
    try {
      const base = (window as unknown as { __BASE_PATH__?: string }).__BASE_PATH__ ?? "";
      const res = await fetch(`${base}/api/webauthn/credentials/${id}/revoke`, { method: "POST" });
      if (!res.ok) {
        const err = await res.json();
        toastError(err.error || "Failed to revoke");
      }
      await fetchCredentials();
    } catch (err) {
      toastError(errorMessage(err));
    }
    revoking = false;
  }

  async function handleRevokeFileKey(id: string) {
    if (!confirm("Revoke this SSH key? This is permanent and cannot be undone.")) return;
    revoking = true;
    try {
      const base = (window as unknown as { __BASE_PATH__?: string }).__BASE_PATH__ ?? "";
      const res = await fetch(`${base}/api/keys/${id}`, { method: "DELETE" });
      if (!res.ok) {
        const err = await res.json();
        toastError(err.error || "Failed to revoke");
      }
      await fetchSshKeys();
    } catch (err) {
      toastError(errorMessage(err));
    }
    revoking = false;
  }

  async function handleRegister() {
    registering = true;
    try {
      const result = await startPasskeyRegistration($account?.name);
      await fetchCredentials();
      // Start inline rename on the newly registered passkey
      editingId = result.credentialId;
      editLabel = result.label;
    } catch (err) {
      toastError(`Registration failed: ${errorMessage(err)}`);
    }
    registering = false;
  }

  function startRename(id: string, currentLabel: string) {
    editingId = id;
    editLabel = currentLabel;
  }

  async function saveRename() {
    if (!editingId || !editLabel.trim()) return;
    try {
      await renamePasskey(editingId, editLabel.trim());
    } catch (err) {
      toastError(errorMessage(err));
    }
    editingId = null;
  }

  function cancelRename() {
    editingId = null;
  }

  function handleRenameKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") saveRename();
    if (e.key === "Escape") cancelRename();
  }

  function shortFingerprint(fp: string | null): string {
    if (!fp) return "—";
    return fp.length > 20 ? `${fp.slice(0, 20)}...` : fp;
  }

  function formatDate(iso: string | null): string {
    if (!iso) return "Never";
    return iso.slice(0, 10);
  }

  const hasAuthorizedKeys = $derived($credentials.some((pk) => pk.authorizedKeysEntry));
  const fileKeys = $derived($sshKeys.filter((k) => k.type === "file"));
</script>

<section>
  <!-- Passkeys -->
  <h2>Passkeys</h2>
  <SettingsList empty={$credentials.length === 0} emptyText="No passkeys registered">
    {#each $credentials as pk (pk.id)}
      <SettingsRow>
        {#snippet primary()}
          {#if editingId === pk.id}
            <!-- svelte-ignore a11y_autofocus -->
            <input
              type="text"
              class="inline-rename"
              bind:value={editLabel}
              onkeydown={handleRenameKeydown}
              onblur={cancelRename}
              autofocus
            />
          {:else}
            <button
              class="row-label label-btn"
              class:revoked={pk.revoked}
              title="Rename"
              disabled={pk.revoked}
              onclick={() => startRename(pk.id, pk.label)}>{pk.label}</button
            >
          {/if}
          {#if pk.revoked}
            <span class="badge badge-unavailable">revoked</span>
          {:else}
            <span class="badge badge-available">active</span>
          {/if}
          <span class="meta-mono">{pk.algorithm}</span>
        {/snippet}
        {#snippet secondary()}
          <span title={pk.fingerprint ?? ""}>{shortFingerprint(pk.fingerprint)}</span>
          <span class="row-dot">·</span>created {formatDate(pk.createdAt)}
          <span class="row-dot">·</span>last used {formatDate(pk.lastUsedAt)}
        {/snippet}
        {#snippet actions()}
          {#if pk.authorizedKeysEntry && !pk.revoked}
            <button
              class="btn btn-secondary"
              title="Copy SSH public key"
              onclick={(e) =>
                copyKey(
                  `${pk.authorizedKeysEntry} ${sshComment(pk.label)}`,
                  e.currentTarget as HTMLButtonElement,
                )}>Copy SSH PubKey</button
            >
          {/if}
          {#if !pk.revoked}
            <button
              class="btn btn-secondary"
              disabled={revoking}
              onclick={() => handleRevoke(pk.id)}>Revoke</button
            >
          {/if}
        {/snippet}
      </SettingsRow>
    {/each}
  </SettingsList>

  <div class="register-section">
    <button class="btn btn-primary" disabled={registering} onclick={handleRegister}>
      {registering ? "Waiting for passkey..." : "Register New Passkey"}
    </button>
  </div>

  {#if hasAuthorizedKeys}
    <div class="settings-info">
      <h3>SSH Server Setup</h3>
      <p>Add this line to <code>/etc/ssh/sshd_config</code> on your remote server:</p>
      <pre
        class="code-block">PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com</pre>
      <p>Then add the passkey's SSH public key to <code>~/.ssh/authorized_keys</code>.</p>
    </div>
  {/if}

  <!-- File-based SSH Keys (admin only) -->
  {#if $account?.isAdmin && fileKeys.length > 0}
    <h2 class="section-divider">File-Based SSH Keys</h2>
    <SettingsList>
      {#each fileKeys as k (k.id)}
        <SettingsRow>
          {#snippet primary()}
            <span class="row-label" class:revoked={k.revoked}>{k.label}</span>
            {#if k.revoked}
              <span class="badge badge-unavailable">revoked</span>
            {:else if !k.available}
              <span class="badge badge-unavailable">unavailable</span>
            {:else}
              <span class="badge badge-available">available</span>
            {/if}
            <span class="meta-mono">{k.algorithm}</span>
          {/snippet}
          {#snippet secondary()}
            <span title={k.fingerprint ?? ""}>{shortFingerprint(k.fingerprint)}</span>
            <span class="row-dot">·</span>created {formatDate(k.createdAt)}
            <span class="row-dot">·</span>last used {formatDate(k.lastUsedAt)}
          {/snippet}
          {#snippet actions()}
            {#if k.authorizedKeysEntry && !k.revoked}
              <button
                class="btn btn-secondary"
                title="Copy SSH public key"
                onclick={(e) =>
                  copyKey(k.authorizedKeysEntry!, e.currentTarget as HTMLButtonElement)}
                >Copy SSH PubKey</button
              >
            {/if}
            {#if !k.revoked}
              <button
                class="btn btn-secondary"
                disabled={revoking}
                onclick={() => handleRevokeFileKey(k.id)}>Revoke</button
              >
            {/if}
          {/snippet}
        </SettingsRow>
      {/each}
    </SettingsList>
  {/if}
</section>

<style>
  h2 {
    font-size: 0.75rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .section-divider {
    margin-top: 2rem;
  }

  .row-label {
    font-weight: 600;
    font-size: var(--body-md);
    color: var(--on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 100%;
  }

  .row-label.revoked {
    opacity: 0.5;
  }

  .meta-mono {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    color: var(--on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .row-dot {
    color: var(--on-surface-faint);
    margin: 0 var(--space-2);
  }

  .register-section {
    margin-top: var(--space-5);
  }

  .label-btn {
    background: none;
    border: none;
    color: var(--on-surface);
    cursor: pointer;
    padding: 0;
    font: inherit;
    text-align: left;
  }

  .label-btn:hover:not(:disabled) {
    color: var(--primary);
    text-decoration: underline;
  }

  .label-btn:disabled {
    cursor: default;
  }

  .inline-rename {
    width: 100%;
    padding: var(--space-1) 0;
    border: none;
    border-bottom: 1px solid var(--primary);
    background: transparent;
    color: var(--on-surface);
    font: inherit;
    font-size: var(--body-md);
  }

  .inline-rename:focus {
    outline: none;
    box-shadow: 0 2px 0 -1px var(--primary);
  }
</style>
