<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<!--
  Transfer strip (#263): what an MCP agent is moving — or moved — through this
  session's file tools. Nobody is prompted for these; this is where a human
  watching the terminal sees them. Live `terminal:file` frames (and the attach
  snapshot after a reconnect) update the list; the session's finished history
  is read once from the audit log. Renders nothing until there is something to
  show, so sessions that never touch a file look exactly as before.
-->
<script lang="ts">
  import { onMount } from "svelte";
  import {
    formatBytes,
    isUnfinished,
    loadSessionHistory,
    mergeHistory,
    shortSha,
    transferProgress,
    transferVerb,
    upsertTransfer,
    viewFromEvent,
    type TransferView,
  } from "$lib/stores/file-transfers.js";
  import { get } from "svelte/store";
  import { onWsMessage, wsConnected } from "$lib/stores/ws.js";

  interface Props {
    sessionId: string;
  }

  let { sessionId }: Props = $props();

  let transfers = $state<TransferView[]>([]);
  let expanded = $state(false);

  // The headline: an in-flight transfer if there is one, else the latest.
  const headline = $derived(transfers.find((t) => isUnfinished(t.status)) ?? transfers[0]);
  const running = $derived(transfers.filter((t) => isUnfinished(t.status)).length);

  onMount(() => {
    const off = onWsMessage((msg) => {
      if (msg.type === "terminal:file" && msg.sessionId === sessionId) {
        transfers = upsertTransfer(transfers, viewFromEvent(msg));
      }
    });
    void loadHistory();
    // A reconnect refetches: a transfer that finished while the socket was
    // down lost its final frame, and the attach snapshot only lists
    // unfinished ones — the audit log is what settles the stale entry.
    let wasConnected = get(wsConnected);
    const offConnected = wsConnected.subscribe((up) => {
      if (up && !wasConnected) void loadHistory();
      wasConnected = up;
    });
    return () => {
      off();
      offConnected();
    };
  });

  // History is best effort: the strip is useful from live frames alone.
  async function loadHistory() {
    try {
      // Pages are followed until every entry still shown as in flight has
      // been found in the log, however far back it sits.
      const unsettled = transfers.filter((t) => isUnfinished(t.status)).map((t) => t.transferId);
      const history = await loadSessionHistory(sessionId, unsettled);
      // Merge into the list as it is NOW: frames that arrived during the
      // fetch are already in `transfers` and must not be overwritten by a
      // snapshot taken before the await.
      transfers = mergeHistory(transfers, history);
    } catch {
      // keep what the socket delivered
    }
  }

  function statusLabel(t: TransferView): string {
    if (t.status === "pending") return "link issued";
    if (t.status === "active") return "in progress";
    return t.status;
  }

  function sizeLabel(t: TransferView): string {
    if (t.direction === "list") return "";
    if (isUnfinished(t.status) && t.totalBytes !== null) {
      return `${formatBytes(t.bytes)} / ${formatBytes(t.totalBytes)}`;
    }
    return formatBytes(t.bytes);
  }
</script>

{#snippet line(t: TransferView)}
  <span class="dot {t.status}" aria-hidden="true"></span>
  <span class="who">{t.mcpClientName ?? "agent"}</span>
  <span class="verb">{transferVerb(t)}</span>
  <span class="path" title={t.path}><bdi dir="ltr">{t.path}</bdi></span>
  {#if sizeLabel(t)}
    <span class="sep">·</span><span class="meta">{sizeLabel(t)}</span>
  {/if}
  {#if t.sha256 && !isUnfinished(t.status)}
    <span class="sep">·</span><span class="meta" title={t.sha256}>sha256 {shortSha(t.sha256)}</span>
  {/if}
  {#if t.status !== "completed"}
    <span class="sep">·</span><span class="state {t.status}">{statusLabel(t)}</span>
  {/if}
  {#if t.truncated}
    <span class="sep">·</span><span class="state failed" title="The file grew after it was copied"
      >grew during copy</span
    >
  {/if}
{/snippet}

{#if headline}
  <div class="transfer-strip" class:expanded>
    <button
      type="button"
      class="headline"
      aria-expanded={expanded}
      title={expanded ? "Hide file activity" : "Show file activity"}
      onclick={() => (expanded = !expanded)}
    >
      <span class="line">{@render line(headline)}</span>
      <span class="count">
        {#if running > 1}{running} active ·
        {/if}{transfers.length}
        {transfers.length === 1 ? "file op" : "file ops"}
        <span class="caret" aria-hidden="true">{expanded ? "▾" : "▸"}</span>
      </span>
    </button>

    {#if isUnfinished(headline.status) && headline.status !== "pending"}
      {@const p = transferProgress(headline)}
      <div
        class="progress"
        class:indeterminate={p === null}
        role="progressbar"
        aria-label="Transfer progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={p === null ? undefined : Math.round(p * 100)}
      >
        <div class="bar" style:width={p === null ? undefined : `${p * 100}%`}></div>
      </div>
    {/if}

    {#if expanded}
      <ul class="list">
        {#each transfers as t (t.transferId)}
          <li>
            <span class="line">{@render line(t)}</span>
            {#if t.error}
              <span class="detail error">{t.error}</span>
            {/if}
            {#if t.cleanup === "failed" && t.stagingPath}
              <span class="detail error">Leftover staging directory: {t.stagingPath}</span>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </div>
{/if}

<style>
  .transfer-strip {
    flex: none;
    background: var(--surface-container-low);
    border-bottom: 1px solid var(--outline-variant);
    font-family: var(--font-mono);
    font-size: var(--label-md);
    color: var(--on-surface-variant);
  }

  .headline {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    width: 100%;
    padding: var(--space-2) var(--space-4);
    background: none;
    border: none;
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: pointer;
  }

  .headline:hover {
    background: var(--surface-container);
  }

  .line {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-width: 0;
  }

  .path {
    color: var(--on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    /* Keep the file name visible when the path is long: an RTL box overflows
       (and gets its ellipsis) on the left. The text itself sits in an
       isolated LTR <bdi>, otherwise the leading "/" is neutral punctuation
       in an RTL run and is drawn at the END ("home/x/file/"). */
    direction: rtl;
    text-align: left;
    min-width: 4rem;
  }

  .who,
  .verb,
  .meta,
  .state,
  .sep,
  .count {
    flex: none;
    white-space: nowrap;
  }

  .who {
    color: var(--on-surface);
  }

  .sep {
    color: var(--on-surface-faint);
  }

  .count {
    color: var(--on-surface-faint);
    font-size: var(--label-sm);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  .caret {
    margin-left: var(--space-2);
  }

  .dot {
    flex: none;
    width: 6px;
    height: 6px;
    background: var(--on-surface-faint);
  }

  .dot.completed {
    background: var(--primary);
  }

  .dot.active,
  .dot.pending {
    background: var(--secondary);
  }

  .dot.failed,
  .dot.expired {
    background: var(--error);
  }

  .state.failed,
  .state.expired {
    color: var(--error);
  }

  .state.active,
  .state.pending {
    color: var(--secondary);
  }

  .progress {
    height: 2px;
    background: var(--surface-container-highest);
    overflow: hidden;
  }

  .bar {
    height: 100%;
    background: var(--primary);
    transition: width 0.2s linear;
  }

  .indeterminate .bar {
    width: 30%;
    animation: slide 1.2s ease-in-out infinite;
  }

  @keyframes slide {
    from {
      transform: translateX(-100%);
    }
    to {
      transform: translateX(340%);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .indeterminate .bar {
      animation: none;
      width: 100%;
      opacity: 0.5;
    }
  }

  .list {
    list-style: none;
    margin: 0;
    padding: 0 var(--space-4) var(--space-3);
    max-height: 12rem;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .list li {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .detail {
    padding-left: calc(6px + var(--space-2));
    white-space: normal;
    overflow-wrap: anywhere;
  }

  .detail.error {
    color: var(--error);
  }
</style>
