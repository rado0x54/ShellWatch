<script lang="ts">
  import { onMount } from "svelte";
  import { get } from "svelte/store";
  import Identicon from "$lib/components/Identicon.svelte";
  import { account } from "$lib/stores/account.js";
  import { basePath } from "$lib/stores/connection.js";

  interface AccountEntry {
    id: string;
    name: string;
    type: string;
    isAdmin: boolean;
    enabled: boolean;
    maxSessions: number;
    lastUsedAt: string | null;
    createdAt: string;
  }

  let accounts = $state<AccountEntry[]>([]);
  let deleting = $state(false);

  async function fetchAccounts() {
    const base = get(basePath);
    const res = await fetch(`${base}/api/accounts`);
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
    const base = get(basePath);
    const res = await fetch(`${base}/api/accounts/${id}`, { method: "DELETE" });
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

  {#if !$account?.isAdmin}
    <p class="no-access">Admin access required.</p>
  {:else}
    <table class="settings-table">
      <thead>
        <tr>
          <th></th>
          <th>Name</th>
          <th>Type</th>
          <th>Role</th>
          <th>Sessions</th>
          <th>Created</th>
          <th>Last Active</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each accounts as acct (acct.id)}
          <tr>
            <td><Identicon uuid={acct.id} size={28} /></td>
            <td>{acct.name}</td>
            <td>{acct.type}</td>
            <td>
              {#if acct.isAdmin}
                <span class="badge badge-admin">admin</span>
              {:else}
                <span class="badge badge-user">user</span>
              {/if}
            </td>
            <td class="muted">{acct.maxSessions}</td>
            <td>{formatDate(acct.createdAt)}</td>
            <td>{formatDate(acct.lastUsedAt)}</td>
            <td>
              {#if !acct.isAdmin}
                <button
                  class="btn btn-secondary btn-sm"
                  disabled={deleting}
                  onclick={() => handleDelete(acct.id, acct.name)}
                >
                  Delete
                </button>
              {/if}
            </td>
          </tr>
        {/each}
        {#if accounts.length === 0}
          <tr><td colspan="8" class="empty">No accounts found</td></tr>
        {/if}
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

  .badge-admin {
    color: var(--accent);
    font-weight: 600;
    font-size: 0.75rem;
  }

  .badge-user {
    color: var(--text-muted);
    font-size: 0.75rem;
  }

  .btn-sm {
    font-size: 0.7rem;
    padding: 0.2rem 0.5rem;
  }

  .muted {
    color: var(--text-muted);
  }

  .empty {
    color: #555;
  }

  .no-access {
    color: var(--text-muted);
    font-size: 0.85rem;
  }
</style>
