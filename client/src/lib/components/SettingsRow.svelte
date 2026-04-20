<script lang="ts">
  import type { Snippet } from "svelte";

  interface Props {
    primary: Snippet;
    /** Address / fingerprint / created-at — small mono line below the primary row. */
    secondary?: Snippet;
    /** Long plain-text detail (description, etc.) shown behind a disclosure. */
    detail?: string | null;
    /** Rich collapsible content — takes precedence over `detail` if both set. */
    detailSlot?: Snippet;
    /** Text shown next to the disclosure caret (e.g. "Description"). */
    detailLabel?: string;
    /** Right-aligned Edit/Delete buttons. */
    actions?: Snippet;
  }

  let {
    primary,
    secondary,
    detail,
    detailSlot,
    detailLabel = "Details",
    actions,
  }: Props = $props();

  const hasDetail = $derived(!!detailSlot || (typeof detail === "string" && detail.length > 0));
</script>

<div class="row">
  <div class="row-head">
    <div class="row-primary">{@render primary()}</div>
    {#if actions}
      <div class="row-actions">{@render actions()}</div>
    {/if}
  </div>

  {#if secondary}
    <div class="row-secondary">{@render secondary()}</div>
  {/if}

  {#if hasDetail}
    <details class="row-detail">
      <summary>{detailLabel}</summary>
      <div class="row-detail-body">
        {#if detailSlot}{@render detailSlot()}{:else}{detail}{/if}
      </div>
    </details>
  {/if}
</div>

<style>
  .row {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding: var(--space-4) var(--space-5);
    background: var(--surface-container-low);
  }

  .row + :global(.row) {
    margin-top: var(--space-1);
  }

  .row-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    min-width: 0;
  }

  .row-primary {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    flex-wrap: wrap;
    min-width: 0;
    flex: 1;
  }

  .row-actions {
    display: flex;
    gap: var(--space-2);
    flex-shrink: 0;
  }

  .row-secondary {
    font-family: var(--font-mono);
    font-size: var(--label-md);
    color: var(--on-surface-variant);
    word-break: break-all;
    overflow-wrap: anywhere;
  }

  .row-detail {
    font-size: var(--body-md);
  }

  .row-detail > summary {
    cursor: pointer;
    user-select: none;
    list-style: none;
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--on-surface-variant);
    padding: var(--space-1) 0;
    display: flex;
    align-items: center;
    gap: var(--space-2);
    transition: color 0.15s;
  }

  .row-detail > summary::-webkit-details-marker {
    display: none;
  }

  .row-detail > summary::before {
    content: "▸";
    display: inline-block;
    font-size: 0.7em;
    transition: transform 0.15s;
  }

  .row-detail[open] > summary::before {
    transform: rotate(90deg);
  }

  .row-detail > summary:hover {
    color: var(--on-surface);
  }

  .row-detail-body {
    padding: var(--space-3) 0 var(--space-2);
    color: var(--on-surface-variant);
    line-height: 1.5;
    white-space: pre-wrap;
  }

  /* Mobile: actions wrap under the primary row; stop squeezing the label. */
  @media (max-width: 768px) {
    .row-head {
      flex-direction: column;
      align-items: stretch;
      gap: var(--space-3);
    }

    .row-actions {
      justify-content: flex-end;
    }
  }
</style>
