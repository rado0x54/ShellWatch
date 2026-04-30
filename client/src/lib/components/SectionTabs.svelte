<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/state";

  type Pathname = import("$app/types").Pathname;

  interface Props {
    tabs: { path: Pathname; label: string }[];
    /**
     * Accessible label for the navigation region. Used both for the <nav>
     * landmark's aria-label and the visually-hidden <label> wrapping the
     * mobile <select>. Plural form reads naturally in both contexts
     * (e.g. "Settings sections", "Admin sections").
     */
    label: string;
  }

  let { tabs, label }: Props = $props();

  const currentPath = $derived(page.url.pathname);

  function handleSelect(event: Event) {
    const target = event.currentTarget as HTMLSelectElement;
    // The option value IS a registered route, so the cast is safe — `goto`
    // only types Pathname for compile-time safety, the runtime contract is
    // "any string the router knows about". The `tabs` prop is the source of
    // truth: every <option value> here was rendered from tab.path.
    goto(resolve(target.value as Pathname));
  }
</script>

<!--
  Two parallel navigations wrapped in a single <nav> landmark: a horizontal
  tab strip for desktop, and a native <select> for mobile (≤ 768px). Toggled
  via CSS so each renders only at its breakpoint. Native select is free a11y
  + the iOS wheel picker / Android sheet, so we don't need a custom popover.
-->
<nav class="section-tabs" aria-label={label}>
  <div class="tabs-strip">
    {#each tabs as tab (tab.path)}
      <button
        class="tab"
        class:active={currentPath === tab.path}
        onclick={() => goto(resolve(tab.path))}
      >
        {tab.label}
      </button>
    {/each}
  </div>

  <label class="select-wrap">
    <span class="visually-hidden">{label}</span>
    <select class="select" value={currentPath} onchange={handleSelect}>
      {#each tabs as tab (tab.path)}
        <option value={tab.path}>{tab.label}</option>
      {/each}
    </select>
  </label>
</nav>

<style>
  .section-tabs {
    margin-bottom: 1.5rem;
  }

  .tabs-strip {
    display: flex;
    gap: 0;
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

  /* Mobile-only dropdown — hidden on desktop. */
  .select-wrap {
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
    /* Swap horizontal tab strip for a native dropdown — see header comment. */
    .tabs-strip {
      display: none;
    }

    .select-wrap {
      display: block;
    }

    .select {
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

    .select:focus {
      outline: none;
      border-color: var(--primary);
    }
  }
</style>
