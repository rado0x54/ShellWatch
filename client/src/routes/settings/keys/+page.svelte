<script lang="ts">
  import { onMount } from "svelte";
  import { account } from "$lib/stores/account.js";
  import { fetchSshKeys, sshKeys } from "$lib/stores/keys.js";
  import {
    credentials,
    fetchCredentials,
    renamePasskey,
    startPasskeyRegistration,
  } from "$lib/stores/webauthn.js";

  let showModal = $state(false);
  let modalLabel = $state("");
  let modalDesc = $state("");
  let revoking = $state(false);
  let pendingCredentialId: string | null = null;

  onMount(() => {
    fetchCredentials();
    fetchSshKeys();
  });

  function copyKey(key: string, btn: HTMLButtonElement) {
    navigator.clipboard.writeText(key);
    const original = btn.innerHTML;
    btn.innerHTML = "&#10003;";
    setTimeout(() => {
      btn.innerHTML = original;
    }, 1500);
  }

  async function handleRevoke(id: string) {
    const activeCount = $credentials.filter((c) => !c.revoked).length;
    if (activeCount <= 1) {
      alert("Cannot revoke the last active passkey.");
      return;
    }
    if (!confirm("Revoke this passkey? This is permanent and cannot be undone.")) return;
    revoking = true;
    try {
      const base = (window as unknown as { __BASE_PATH__?: string }).__BASE_PATH__ ?? "";
      const res = await fetch(`${base}/api/webauthn/credentials/${id}/revoke`, { method: "POST" });
      if (!res.ok) {
        const err = await res.json();
        alert(err.error || "Failed to revoke");
      }
      await fetchCredentials();
    } catch (err) {
      alert((err as Error).message);
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
        alert(err.error || "Failed to revoke");
      }
      await fetchSshKeys();
    } catch (err) {
      alert((err as Error).message);
    }
    revoking = false;
  }

  async function handleRegister() {
    try {
      const result = await startPasskeyRegistration($account?.name);
      pendingCredentialId = result.credentialId;
      modalLabel = result.suggestedLabel;
      modalDesc = `Detected: ${result.suggestedLabel}. Change the label if you like.`;
      showModal = true;
    } catch (err) {
      alert(`Registration failed: ${(err as Error).message}`);
    }
  }

  async function handleSave() {
    if (!pendingCredentialId) return;
    const label = modalLabel.trim();
    if (!label) return;
    try {
      await renamePasskey(pendingCredentialId, label);
    } catch (err) {
      alert(`Failed to save label: ${(err as Error).message}`);
    }
    showModal = false;
    pendingCredentialId = null;
  }

  function handleCancel() {
    showModal = false;
    pendingCredentialId = null;
  }

  function handleModalKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") handleSave();
    if (e.key === "Escape") handleCancel();
  }

  function shortFingerprint(fp: string): string {
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
          <td>{pk.label}</td>
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
                  copyKey(pk.authorizedKeysEntry!, e.currentTarget as HTMLButtonElement)}
              >&#128203; SSH PubKey</button>
            {/if}
            {#if !pk.revoked}
              <button
                class="btn btn-secondary btn-sm"
                disabled={revoking}
                onclick={() => handleRevoke(pk.id)}
              >Revoke</button>
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
    <button class="btn btn-primary" onclick={handleRegister}>Register New Passkey</button>
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
                >&#128203; SSH PubKey</button>
              {/if}
              {#if !k.revoked}
                <button
                  class="btn btn-secondary btn-sm"
                  disabled={revoking}
                  onclick={() => handleRevokeFileKey(k.id)}
                >Revoke</button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}

  {#if showModal}
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="modal-overlay" onclick={handleCancel}>
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div class="modal" onclick={(e) => e.stopPropagation()}>
        <h3>Name Your Passkey</h3>
        <p class="modal-desc">{modalDesc}</p>
        <!-- svelte-ignore a11y_autofocus -->
        <input
          type="text"
          bind:value={modalLabel}
          placeholder="e.g., YubiKey 5 NFC"
          onkeydown={handleModalKeydown}
          autofocus
          style="width: 100%; margin-bottom: 1rem"
        />
        <div class="modal-actions">
          <button class="btn btn-secondary" onclick={handleCancel}>Cancel</button>
          <button class="btn btn-primary" onclick={handleSave}>Save</button>
        </div>
      </div>
    </div>
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

  .modal-desc {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0.75rem 0;
  }

  .modal-actions {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
  }
</style>
