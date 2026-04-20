<script lang="ts">
  import { onMount } from "svelte";
  import Identicon from "$lib/components/Identicon.svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";

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

  async function fetchAccounts() {
    const res = await fetch("/api/accounts");
    if (res.ok) {
      const data = await res.json();
      accounts = data.accounts;
    }
  }

  onMount(fetchAccounts);

  async function handleDelete(id: string, name: string) {
    if (
      !confirm(
        `Delete account "${name}"? This will permanently remove all their passkeys, endpoints, API keys, and sessions.`,
      )
    )
      return;
    deleting = true;
    const res = await fetch(`/api/accounts/${id}`, { method: "DELETE" });
    if (!res.ok) {
      const err = await res.json();
      alert(err.error || "Failed to delete account");
    }
    await fetchAccounts();
    deleting = false;
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
              class="btn btn-secondary"
              disabled={deleting}
              onclick={() => handleDelete(acct.id, acct.name)}
            >
              Delete
            </button>
          {/if}
        {/snippet}
      </SettingsRow>
    {/each}
  </SettingsList>
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
</style>
