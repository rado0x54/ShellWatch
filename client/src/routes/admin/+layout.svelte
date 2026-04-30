<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/state";
  import { account } from "$lib/stores/account.js";

  let { children } = $props();

  type Pathname = import("$app/types").Pathname;
  const tabs: { path: Pathname; label: string }[] = [
    { path: "/admin/general", label: "General" },
    { path: "/admin/accounts", label: "Accounts" },
  ];

  const currentPath = $derived(page.url.pathname);

  function handleSelect(event: Event) {
    const target = event.currentTarget as HTMLSelectElement;
    goto(resolve(target.value as Pathname));
  }
</script>

<div class="settings-page">
  <div class="settings-header">
    <h1>Admin</h1>
  </div>

  {#if !$account?.isAdmin}
    <p class="no-access">Admin access required.</p>
  {:else}
    <!-- Tab strip + dropdown sibling, same pattern as settings/+layout.svelte. -->
    <nav class="settings-tabs" aria-label="Admin sections">
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

    <label class="settings-select-wrap">
      <span class="visually-hidden">Admin section</span>
      <select class="settings-select" value={currentPath} onchange={handleSelect}>
        {#each tabs as tab (tab.path)}
          <option value={tab.path}>{tab.label}</option>
        {/each}
      </select>
    </label>

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

  /* Mobile-only dropdown — hidden on desktop. */
  .settings-select-wrap {
    display: none;
  }

  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  @media (max-width: 768px) {
    .settings-page {
      padding: 1rem;
    }

    .settings-tabs {
      display: none;
    }

    .settings-select-wrap {
      display: block;
      margin-bottom: 1.5rem;
    }

    .settings-select {
      width: 100%;
      padding: 0.6rem 2.25rem 0.6rem 0.85rem;
      background: var(--surface-container-low);
      color: var(--on-surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: var(--label-sm);
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      cursor: pointer;
      appearance: none;
      background-image:
        linear-gradient(45deg, transparent 50%, var(--on-surface-variant) 50%),
        linear-gradient(135deg, var(--on-surface-variant) 50%, transparent 50%);
      background-position:
        right 1rem top 50%,
        right 0.65rem top 50%;
      background-size:
        6px 6px,
        6px 6px;
      background-repeat: no-repeat;
    }

    .settings-select:focus {
      outline: none;
      border-color: var(--primary);
    }
  }
</style>
