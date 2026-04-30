<script lang="ts">
  import SectionTabs from "$lib/components/SectionTabs.svelte";
  import { account } from "$lib/stores/account.js";

  let { children } = $props();

  type Pathname = import("$app/types").Pathname;
  const tabs: { path: Pathname; label: string }[] = [
    { path: "/admin/general", label: "General" },
    { path: "/admin/accounts", label: "Accounts" },
  ];
</script>

<div class="settings-page">
  <div class="settings-header">
    <h1>Admin</h1>
  </div>

  {#if !$account?.isAdmin}
    <p class="no-access">Admin access required.</p>
  {:else}
    <SectionTabs {tabs} label="Admin sections" />

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
  }
</style>
