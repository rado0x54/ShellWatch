<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/state";

  let { children } = $props();

  type Pathname = import("$app/types").Pathname;
  const tabs: { path: Pathname; label: string }[] = [
    { path: "/settings/general", label: "General" },
    { path: "/settings/endpoints", label: "Endpoints" },
    { path: "/settings/keys", label: "Keys" },
    { path: "/settings/api-keys", label: "API Keys" },
    { path: "/settings/notifications", label: "Notifications" },
  ];

  const currentPath = $derived(page.url.pathname);

  function handleSelect(event: Event) {
    const target = event.currentTarget as HTMLSelectElement;
    // The option value IS a registered route, so the cast is safe — `goto`
    // only types Pathname for compile-time safety, the runtime contract is
    // "any string the router knows about". `tabs` is the source of truth.
    goto(resolve(target.value as Pathname));
  }
</script>

<div class="settings-page">
  <div class="settings-header">
    <h1>Settings</h1>
  </div>

  <!--
    Two parallel navigations: a horizontal tab strip for desktop, and a
    native <select> for mobile (≤ 768px). Toggled via CSS so each renders
    only at its breakpoint. Native select is free a11y + the iOS wheel
    picker, so we don't need a custom popover here.
  -->
  <nav class="settings-tabs" aria-label="Settings sections">
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
    <span class="visually-hidden">Settings section</span>
    <select class="settings-select" value={currentPath} onchange={handleSelect}>
      {#each tabs as tab (tab.path)}
        <option value={tab.path}>{tab.label}</option>
      {/each}
    </select>
  </label>

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

    /* Swap horizontal tab strip for a native dropdown — see header comment. */
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
      /* Native dropdown indicator looks inconsistent across browsers, so we
         draw our own chevron and hide the default. */
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
