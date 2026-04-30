<script lang="ts">
  import SectionTabs from "$lib/components/SectionTabs.svelte";

  let { children } = $props();

  type Pathname = import("$app/types").Pathname;
  const tabs: { path: Pathname; label: string }[] = [
    { path: "/settings/general", label: "General" },
    { path: "/settings/endpoints", label: "Endpoints" },
    { path: "/settings/keys", label: "Keys" },
    { path: "/settings/api-keys", label: "API Keys" },
    { path: "/settings/notifications", label: "Notifications" },
  ];
</script>

<div class="settings-page">
  <div class="settings-header">
    <h1>Settings</h1>
  </div>

  <SectionTabs {tabs} label="Settings sections" />

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
    font-family: var(--font-display);
    font-size: var(--display-md);
    font-weight: 600;
    letter-spacing: -0.035em;
  }

  .settings-content {
    min-height: 0;
  }

  @media (max-width: 768px) {
    .settings-page {
      padding: 1rem;
    }
  }
</style>
