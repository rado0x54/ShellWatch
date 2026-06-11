<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { apiFetch } from "$lib/api.js";
  import { onMount } from "svelte";
  import Identicon from "$lib/components/Identicon.svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";
  import ConfirmDialog from "$lib/components/ConfirmDialog.svelte";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";

  interface AccountEntry {
    id: string;
    name: string;
    isAdmin: boolean;
    enabled: boolean;
    maxSessions: number;
    lastUsedAt: string | null;
    createdAt: string;
  }

  let accounts = $state<AccountEntry[]>([]);
  let deleting = $state(false);
  let deleteTarget = $state<AccountEntry | null>(null);
  let typedName = $state("");

  async function fetchAccounts() {
    const res = await apiFetch("/api/accounts");
    if (res.ok) {
      const data = await res.json();
      accounts = data.accounts;
    }
  }

  onMount(fetchAccounts);

  function openDelete(acct: AccountEntry) {
    deleteTarget = acct;
    typedName = "";
  }

  function closeDelete() {
    if (deleting) return;
    deleteTarget = null;
    typedName = "";
  }

  async function handleDelete() {
    if (!deleteTarget || typedName !== deleteTarget.name) return;
    deleting = true;
    try {
      const res = await apiFetch(`/api/accounts/${deleteTarget.id}`, { method: "DELETE" });
      if (!res.ok) {
        const err = await res.json();
        toastError(err.error || "Failed to delete account");
        return;
      }
      deleteTarget = null;
      typedName = "";
      await fetchAccounts();
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      deleting = false;
    }
  }

  function formatDate(iso: string | null): string {
    if (!iso) return "Never";
    return iso.slice(0, 10);
  }
</script>

<section>
  <h2>Accounts</h2>

  <SettingsList empty={accounts.length === 0} emptyText="No accounts found">
    {#each accounts as acct (acct.id)}
      <SettingsRow>
        {#snippet primary()}
          <Identicon uuid={acct.id} size={28} />
          <span class="row-label">{acct.name}</span>
          {#if acct.isAdmin}
            <span class="badge badge-available">admin</span>
          {:else}
            <span class="badge">user</span>
          {/if}
        {/snippet}
        {#snippet secondary()}
          max sessions {acct.maxSessions}
          <span class="row-dot">·</span>created {formatDate(acct.createdAt)}
          <span class="row-dot">·</span>last active {formatDate(acct.lastUsedAt)}
        {/snippet}
        {#snippet actions()}
          {#if !acct.isAdmin}
            <button
              type="button"
              class="btn btn-secondary"
              disabled={deleting}
              onclick={() => openDelete(acct)}
            >
              Delete
            </button>
          {/if}
        {/snippet}
      </SettingsRow>
    {/each}
  </SettingsList>

  {#if deleteTarget}
    <ConfirmDialog
      title="Delete account?"
      confirmLabel="Delete account"
      onConfirm={handleDelete}
      onCancel={closeDelete}
      processing={deleting}
      confirmDisabled={typedName !== deleteTarget.name}
    >
      <p class="modal-desc">
        Permanently remove <strong>{deleteTarget.name}</strong>, all their passkeys, endpoints, API
        keys, and sessions. This cannot be undone.
      </p>
      <label class="confirm-label" for="confirm-name">
        Type <code>{deleteTarget.name}</code> to confirm
      </label>
      <input
        id="confirm-name"
        type="text"
        class="confirm-input"
        bind:value={typedName}
        autocomplete="off"
        autocapitalize="off"
        spellcheck="false"
      />
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

  .confirm-label code {
    font-family: var(--font-mono);
    font-size: 0.85em;
    color: var(--on-surface);
    background: var(--bg-primary);
    padding: 0.05rem 0.3rem;
    border-radius: 3px;
  }

  .confirm-label {
    display: block;
    font-size: 0.78rem;
    color: var(--text-muted);
    margin-bottom: 0.4rem;
  }

  .confirm-input {
    width: 100%;
    box-sizing: border-box;
    padding: 0.45rem 0.6rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--on-surface);
    font: inherit;
    font-family: var(--font-mono);
    font-size: 0.85rem;
  }

  .confirm-input:focus {
    outline: none;
    border-color: var(--primary);
  }
</style>
