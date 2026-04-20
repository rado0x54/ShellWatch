<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/state";
  import { account } from "$lib/stores/account.js";

  let { children } = $props();

  const tabs: { path: import("$app/types").Pathname; label: string }[] = [
    { path: "/admin/general", label: "General" },
    { path: "/admin/accounts", label: "Accounts" },
  ];

  const currentPath = $derived(page.url.pathname);
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
    font-family: var(--font-display);
    font-size: var(--display-md);
    font-weight: 600;
    letter-spacing: -0.035em;
  }

  .settings-tabs {
    display: flex;
    gap: 0;
    margin-bottom: 1.5rem;
    overflow-x: auto;
    background: var(--surface-container-low);
  }

  .tab {
    padding: var(--space-3) var(--space-5);
    background: none;
    border: none;
    box-shadow: inset 0 -2px 0 transparent;
    color: var(--on-surface-variant);
    font-family: var(--font-mono);
    cursor: pointer;
    font-size: var(--label-sm);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    white-space: nowrap;
    transition:
      color 0.15s,
      box-shadow 0.15s;
  }

  .tab:hover {
    color: var(--on-surface);
  }

  .tab.active {
    color: var(--primary);
    box-shadow: inset 0 -2px 0 var(--primary);
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
