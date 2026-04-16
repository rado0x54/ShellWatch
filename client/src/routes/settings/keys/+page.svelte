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
  <table class="settings-table">
    <thead>
      <tr>
        <th>Label</th>
        <th>Algorithm</th>
        <th>Fingerprint</th>
        <th>Status</th>
        <th>Created</th>
        <th>Last Used</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each $credentials as pk (pk.id)}
        <tr class:revoked={pk.revoked}>
          <td>
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
                class="label-btn"
                title="Rename"
                disabled={pk.revoked}
                onclick={() => startRename(pk.id, pk.label)}>{pk.label}</button
              >
            {/if}
          </td>
          <td>{pk.algorithm}</td>
          <td class="fingerprint">{shortFingerprint(pk.fingerprint)}</td>
          <td>
            {#if pk.revoked}
              <span class="badge badge-revoked">revoked</span>
            {:else}
              <span class="badge badge-available">active</span>
            {/if}
          </td>
          <td>{formatDate(pk.createdAt)}</td>
          <td>{formatDate(pk.lastUsedAt)}</td>
          <td class="actions">
            {#if pk.authorizedKeysEntry && !pk.revoked}
              <button
                class="btn-icon"
                title="Copy SSH public key"
                onclick={(e) =>
                  copyKey(
                    `${pk.authorizedKeysEntry} ${sshComment(pk.label)}`,
                    e.currentTarget as HTMLButtonElement,
                  )}>&#128203; SSH PubKey</button
              >
            {/if}
            {#if !pk.revoked}
              <button
                class="btn btn-secondary btn-sm"
                disabled={revoking}
                onclick={() => handleRevoke(pk.id)}>Revoke</button
              >
            {/if}
          </td>
        </tr>
      {/each}
      {#if $credentials.length === 0}
        <tr><td colspan="7" class="empty">No passkeys registered</td></tr>
      {/if}
    </tbody>
  </table>

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
    <table class="settings-table">
      <thead>
        <tr>
          <th>Label</th>
          <th>Algorithm</th>
          <th>Fingerprint</th>
          <th>Status</th>
          <th>Created</th>
          <th>Last Used</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each fileKeys as k (k.id)}
          <tr class:revoked={k.revoked}>
            <td>{k.label}</td>
            <td>{k.algorithm}</td>
            <td class="fingerprint">{shortFingerprint(k.fingerprint)}</td>
            <td>
              {#if k.revoked}
                <span class="badge badge-revoked">revoked</span>
              {:else if !k.available}
                <span class="badge badge-unavailable">unavailable</span>
              {:else}
                <span class="badge badge-available">available</span>
              {/if}
            </td>
            <td>{formatDate(k.createdAt)}</td>
            <td>{formatDate(k.lastUsedAt)}</td>
            <td class="actions">
              {#if k.authorizedKeysEntry && !k.revoked}
                <button
                  class="btn-icon"
                  title="Copy SSH public key"
                  onclick={(e) =>
                    copyKey(k.authorizedKeysEntry!, e.currentTarget as HTMLButtonElement)}
                  >&#128203; SSH PubKey</button
                >
              {/if}
              {#if !k.revoked}
                <button
                  class="btn btn-secondary btn-sm"
                  disabled={revoking}
                  onclick={() => handleRevokeFileKey(k.id)}>Revoke</button
                >
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
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

  .fingerprint {
    font-family: monospace;
    font-size: 0.75rem;
  }

  .actions {
    display: flex;
    gap: 0.25rem;
    align-items: center;
  }

  .btn-icon {
    background: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 0.15rem 0.35rem;
    border-radius: 3px;
    font-size: 0.75rem;
    cursor: pointer;
    line-height: 1;
  }

  .btn-icon:hover {
    border-color: var(--accent);
    color: var(--accent);
  }

  .btn-sm {
    font-size: 0.7rem;
    padding: 0.2rem 0.5rem;
  }

  .badge-revoked {
    color: var(--red);
  }

  .badge-unavailable {
    color: #b8860b;
  }

  .badge-available {
    color: var(--green, #4ade80);
  }

  tr.revoked td {
    opacity: 0.5;
  }

  .empty {
    color: #555;
  }

  .register-section {
    margin-top: 1rem;
  }

  .label-btn {
    background: none;
    border: none;
    color: var(--text-primary);
    cursor: pointer;
    padding: 0;
    font: inherit;
    text-align: left;
  }

  .label-btn:hover:not(:disabled) {
    color: var(--accent);
    text-decoration: underline;
  }

  .label-btn:disabled {
    cursor: default;
  }

  .inline-rename {
    width: 100%;
    padding: 0.15rem 0.3rem;
    border: 1px solid var(--accent);
    border-radius: 3px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font: inherit;
    font-size: 0.85rem;
  }
</style>
