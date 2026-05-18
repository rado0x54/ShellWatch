<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<!--
  Admin-only view of file-based SSH keys discovered in the configured key
  directory. Lifted out of /settings/keys when that page was renamed to
  "Passkeys" — file keys are an admin concern that doesn't belong next to
  per-user passkey management.
-->
<script lang="ts">
  import { onMount } from "svelte";
  import ConfirmDialog from "$lib/components/ConfirmDialog.svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";
  import { fetchSshKeys, sshKeys } from "$lib/stores/keys.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";

  let revoking = $state(false);
  let revokeTarget = $state<{ id: string; label: string } | null>(null);

  onMount(() => {
    fetchSshKeys();
  });

  const fileKeys = $derived($sshKeys.filter((k) => k.type === "file"));

  function copyKey(key: string, btn: HTMLButtonElement) {
    navigator.clipboard.writeText(key);
    const original = btn.innerHTML;
    btn.innerHTML = "&#10003;";
    setTimeout(() => {
      btn.innerHTML = original;
    }, 1500);
  }

  function shortFingerprint(fp: string | null): string {
    if (!fp) return "—";
    return fp.length > 20 ? `${fp.slice(0, 20)}...` : fp;
  }

  function formatDate(iso: string | null): string {
    if (!iso) return "Never";
    return iso.slice(0, 10);
  }

  function openRevoke(id: string, label: string) {
    revokeTarget = { id, label };
  }

  function closeRevoke() {
    if (revoking) return;
    revokeTarget = null;
  }

  async function handleRevoke() {
    if (!revokeTarget) return;
    revoking = true;
    try {
      const base = (window as unknown as { __BASE_PATH__?: string }).__BASE_PATH__ ?? "";
      const res = await fetch(`${base}/api/keys/${revokeTarget.id}`, { method: "DELETE" });
      if (!res.ok) {
        const err = await res.json();
        toastError(err.error || "Failed to revoke");
        return;
      }
      await fetchSshKeys();
      revokeTarget = null;
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      revoking = false;
    }
  }
</script>

<section>
  <h2>File-Based SSH Keys</h2>

  <SettingsList empty={fileKeys.length === 0} emptyText="No file-based SSH keys discovered">
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
              type="button"
              class="btn btn-secondary"
              title="Copy SSH public key"
              onclick={(e) => copyKey(k.authorizedKeysEntry!, e.currentTarget as HTMLButtonElement)}
              >Copy SSH PubKey</button
            >
          {/if}
          {#if !k.revoked}
            <button
              type="button"
              class="btn btn-secondary"
              disabled={revoking}
              onclick={() => openRevoke(k.id, k.label)}>Revoke</button
            >
          {/if}
        {/snippet}
      </SettingsRow>
    {/each}
  </SettingsList>

  {#if revokeTarget}
    <ConfirmDialog
      title="Revoke SSH key?"
      confirmLabel="Revoke"
      onConfirm={handleRevoke}
      onCancel={closeRevoke}
      processing={revoking}
    >
      <p class="modal-desc">
        Revoke <strong>{revokeTarget.label}</strong>? This is permanent and cannot be undone.
      </p>
    </ConfirmDialog>
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

  .modal-desc {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0 0 var(--space-3);
    line-height: 1.5;
  }
</style>
