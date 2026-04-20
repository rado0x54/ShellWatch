<script lang="ts">
  import type { Snippet } from "svelte";

  interface Props {
    children: Snippet;
    empty?: boolean;
    emptyText?: string;
  }

  let { children, empty = false, emptyText = "Nothing to show" }: Props = $props();
</script>

<div class="list">
  {#if empty}
    <div class="empty">{emptyText}</div>
  {:else}
    {@render children()}
  {/if}
</div>

<style>
  .list {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    background: var(--surface-dim);
  }

  .empty {
    padding: var(--space-5);
    text-align: center;
    color: var(--on-surface-faint);
    font-family: var(--font-mono);
    font-size: var(--label-md);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    background: var(--surface-container-low);
  }
</style>
