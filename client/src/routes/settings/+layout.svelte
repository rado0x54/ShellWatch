<script lang="ts">
import { goto } from "$app/navigation";
import { page } from "$app/stores";

let { children } = $props();

const tabs = [
  { path: "/settings/endpoints", label: "Endpoints" },
  { path: "/settings/keys", label: "SSH Keys" },
  { path: "/settings/passkeys", label: "Passkeys" },
  { path: "/settings/api-keys", label: "API Keys" },
] as const;

const currentPath = $derived($page.url.pathname);
</script>

<div class="settings-page">
  <div class="settings-header">
    <h1>Settings</h1>
  </div>

  <nav class="settings-tabs">
    {#each tabs as tab (tab.path)}
      <button
        class="tab"
        class:active={currentPath === tab.path}
        onclick={() => goto(tab.path)}
      >
        {tab.label}
      </button>
    {/each}
  </nav>

  <div class="settings-content">
    {@render children()}
  </div>
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

  @media (max-width: 768px) {
    .settings-page {
      padding: 1rem;
    }

    .settings-tabs {
      gap: 0;
    }

    .tab {
      padding: 0.5rem 0.75rem;
      font-size: 0.8rem;
    }
  }
</style>
