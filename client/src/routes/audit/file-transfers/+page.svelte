<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<!--
  Audit → File Transfers (#263): every file an MCP agent listed, read, wrote or
  streamed through one of the account's sessions. The file tools need no
  approval, so this log (and the live strip above the terminal) is the record.
-->
<script lang="ts">
  import { onMount } from "svelte";
  import { resolve } from "$app/paths";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";
  import { endpoints } from "$lib/stores/endpoints.js";
  import {
    fetchFileTransfersPage,
    formatBytes,
    isUnfinished,
    type FileTransferRow,
  } from "$lib/stores/file-transfers.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { sessions } from "$lib/stores/ws.js";
  import { errorMessage } from "$lib/utils/error-message.js";

  let rows = $state<FileTransferRow[]>([]);
  let nextCursor = $state<string | null>(null);
  let direction = $state<string>("");
  let tier = $state<string>("");
  let status = $state<string>("");
  let loading = $state(false);
  // A filter change that lands while a fetch is in flight is queued, not
  // dropped: the controls stay enabled, and the list must end up showing the
  // filters the user sees selected.
  let pendingReset = false;

  const endpointLabel = $derived((id: string) => $endpoints.find((e) => e.id === id)?.label ?? id);
  const isLive = $derived((id: string) => $sessions.some((s) => s.sessionId === id));

  onMount(() => {
    void load(true);
  });

  async function load(reset: boolean) {
    if (loading) {
      if (reset) pendingReset = true;
      return;
    }
    loading = true;
    // Captured now: a page that comes back after the filters changed belongs
    // to the old selection and must not be shown under the new one.
    const requested = `${direction}|${tier}|${status}`;
    try {
      const page = await fetchFileTransfersPage(
        {
          direction: direction || undefined,
          tier: tier || undefined,
          status: status || undefined,
        },
        reset ? undefined : (nextCursor ?? undefined),
      );
      if (requested === `${direction}|${tier}|${status}`) {
        rows = reset ? page.rows : [...rows, ...page.rows];
        nextCursor = page.nextCursor;
      }
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      loading = false;
      if (pendingReset) {
        pendingReset = false;
        void load(true);
      }
    }
  }

  function onFilterChange() {
    void load(true);
  }

  function formatTimestamp(iso: string): string {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }

  const directionLabels: Record<string, string> = {
    upload: "write",
    download: "read",
    list: "list",
  };

  function dotClass(s: string): string {
    if (s === "completed") return "ok";
    if (isUnfinished(s)) return "running";
    if (s === "cancelled") return "neutral";
    return "bad";
  }
</script>

<div class="audit-page">
  <div class="audit-filter">
    <div class="filter-group">
      <label class="filter-label" for="direction-filter">Operation</label>
      <select id="direction-filter" bind:value={direction} onchange={onFilterChange}>
        <option value="">All</option>
        <option value="upload">Write (to host)</option>
        <option value="download">Read (from host)</option>
        <option value="list">List directory</option>
      </select>
    </div>
    <div class="filter-group">
      <label class="filter-label" for="tier-filter">Tier</label>
      <select id="tier-filter" bind:value={tier} onchange={onFilterChange}>
        <option value="">All</option>
        <option value="inline">Inline (tool call)</option>
        <option value="link">Link (out of band)</option>
      </select>
    </div>
    <div class="filter-group">
      <label class="filter-label" for="status-filter">Status</label>
      <select id="status-filter" bind:value={status} onchange={onFilterChange}>
        <option value="">All</option>
        <option value="completed">Completed</option>
        <option value="failed">Failed</option>
        <option value="cancelled">Cancelled</option>
        <option value="expired">Expired</option>
        <option value="active">Active</option>
        <option value="pending">Pending</option>
      </select>
    </div>
  </div>

  <SettingsList empty={rows.length === 0 && !loading} emptyText="No file transfers">
    {#each rows as row (row.transferId)}
      <SettingsRow detailLabel="Metadata">
        {#snippet primary()}
          <span class="row-label">
            <span class="xfer-dot {dotClass(row.status)}"></span><span class="row-path"
              >{row.path}</span
            >
          </span>
          <span class="badge badge-kind">{directionLabels[row.direction] ?? row.direction}</span>
          <span class="badge badge-kind">{row.tier}</span>
          {#if row.status !== "completed"}
            <span class="badge badge-status {dotClass(row.status)}">{row.status}</span>
          {/if}
          {#if row.truncated}
            <span class="badge badge-status bad">grew during copy</span>
          {/if}
        {/snippet}
        {#snippet secondary()}
          {endpointLabel(row.endpointId)}<span class="row-dot">·</span>{formatTimestamp(
            row.createdAt,
          )}{#if row.direction !== "list"}<span class="row-dot">·</span>{formatBytes(
              row.bytes,
            )}{/if}{#if row.mcpClientName}<span class="row-dot">·</span>{row.mcpClientName}{/if}
        {/snippet}
        {#snippet detailSlot()}
          <dl class="meta-grid">
            <dt>Transfer</dt>
            <dd>{row.transferId}</dd>
            <dt>Session</dt>
            <dd>
              {#if isLive(row.sessionId)}
                <a href={resolve("/session/[id]", { id: row.sessionId })}>{row.sessionId}</a>
              {:else}
                {row.sessionId}
              {/if}
            </dd>
            <dt>Status</dt>
            <dd>
              {row.status}{row.finishedAt ? ` (${formatTimestamp(row.finishedAt)})` : ""}
            </dd>
            {#if row.error}
              <dt>Error</dt>
              <dd class="bad">{row.error}</dd>
            {/if}
            {#if row.direction !== "list"}
              <dt>Bytes</dt>
              <dd>
                {row.bytes}{row.totalBytes !== null && row.totalBytes !== row.bytes
                  ? ` of ${row.totalBytes}`
                  : ""}
              </dd>
            {/if}
            {#if row.sha256}
              <dt>SHA-256</dt>
              <dd>{row.sha256}</dd>
            {/if}
            {#if row.commitOutcome}
              <dt>Commit</dt>
              <dd class:bad={row.commitOutcome !== "ok"}>
                {row.commitOutcome}{row.commitOutcome === "unknown"
                  ? " — inspect the destination before retrying"
                  : ""}
              </dd>
            {/if}
            {#if row.cleanup}
              <dt>Cleanup</dt>
              <dd class:bad={row.cleanup !== "ok"}>{row.cleanup}</dd>
            {/if}
            {#if row.stagingPath}
              <dt>{row.cleanup === "failed" ? "Leftover staging" : "Staging"}</dt>
              <dd class:bad={row.cleanup === "failed"}>{row.stagingPath}</dd>
            {/if}
            {#if row.clientId}
              <dt>OAuth client</dt>
              <dd>{row.clientId}</dd>
            {/if}
            {#if row.mcpClientName}
              <dt>MCP client</dt>
              <dd>{row.mcpClientName}{row.mcpClientVersion ? ` ${row.mcpClientVersion}` : ""}</dd>
            {/if}
            {#if row.sourceIp}
              <dt>Source IP</dt>
              <dd>{row.sourceIp}</dd>
            {/if}
          </dl>
        {/snippet}
      </SettingsRow>
    {/each}
  </SettingsList>

  <div class="audit-footer">
    {#if nextCursor}
      <button
        type="button"
        class="btn btn-secondary"
        disabled={loading}
        onclick={() => load(false)}
      >
        {loading ? "Loading…" : "Load more"}
      </button>
    {:else if rows.length > 0 && !loading}
      <span class="end-marker">— end of log —</span>
    {/if}
  </div>
</div>

<style>
  .audit-filter {
    display: flex;
    align-items: flex-end;
    flex-wrap: wrap;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }

  .filter-group {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .filter-label {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--on-surface-variant);
  }

  .audit-filter select {
    min-width: 11rem;
  }

  .row-label {
    font-weight: 600;
    font-size: var(--body-md);
    color: var(--on-surface);
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    min-width: 0;
  }

  .row-path {
    font-family: var(--font-mono);
    overflow-wrap: anywhere;
  }

  .xfer-dot {
    flex: none;
    width: 6px;
    height: 6px;
    background: var(--on-surface-faint);
  }

  .xfer-dot.ok {
    background: var(--primary);
  }

  .xfer-dot.running {
    background: var(--secondary);
  }

  .xfer-dot.bad {
    background: var(--error);
  }

  .row-dot {
    color: var(--on-surface-faint);
    margin: 0 var(--space-2);
  }

  .badge-kind {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--on-surface-variant);
  }

  .badge-status {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    color: var(--on-surface-variant);
  }

  .badge-status.bad,
  .bad {
    color: var(--error);
  }

  .meta-grid {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-2) var(--space-4);
    font-family: var(--font-mono);
    font-size: var(--label-md);
  }

  .meta-grid dt {
    color: var(--on-surface-faint);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-size: var(--label-sm);
  }

  .meta-grid dd {
    color: var(--on-surface);
    word-break: break-all;
  }

  .meta-grid dd.bad {
    color: var(--error);
  }

  .audit-footer {
    display: flex;
    justify-content: center;
    padding: var(--space-5) 0;
  }

  .end-marker {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    color: var(--on-surface-faint);
    text-transform: uppercase;
    letter-spacing: 0.14em;
  }
</style>
