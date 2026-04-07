<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/stores";
  import { account } from "$lib/stores/account.js";

  let { children } = $props();

  const tabs = [
    { path: "/admin/general", label: "General" },
    { path: "/admin/accounts", label: "Accounts" },
  ];

  const currentPath = $derived($page.url.pathname);
</script>

<div class="settings-page">
  <div class="settings-header">
    <h1>Admin</h1>
  </div>

  {#if !$account?.isAdmin}
    <p class="no-access">Admin access required.</p>
  {:else}
    <nav class="settings-tabs">
      {#each tabs as tab (tab.path)}
        <button
          class="tab"
          class:active={currentPath === tab.path}
          onclick={() => goto(resolve(tab.path))}
        >
          {tab.label}
        </button>
      {/each}
    </nav>

    <div class="settings-content">
      {@render children()}
    </div>
  {/if}
</div>

<style>
  .settings-page {
    padding: 2rem;
    overflow-y: auto;
    height: 100%;
  }

  .settings-header {
    margin-bottom: 1.5rem;
  }

  .settings-header h1 {
    font-size: 1.5rem;
    font-weight: 600;
  }

  .settings-tabs {
    display: flex;
    gap: 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1.5rem;
    overflow-x: auto;
  }

  .tab {
    padding: 0.5rem 1rem;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 0.85rem;
    font-weight: 500;
    white-space: nowrap;
  }

  .tab:hover {
    color: var(--text-primary);
  }

  .tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  .settings-content {
    min-height: 0;
  }

  .no-access {
    color: var(--text-muted);
    font-size: 0.85rem;
  }

  @media (max-width: 768px) {
    .settings-page {
      padding: 1rem;
    }

    .tab {
      padding: 0.5rem 0.75rem;
      font-size: 0.8rem;
    }
  }
</style>
