<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";
  import { endpoints } from "$lib/stores/endpoints.js";
  import { fetchAuditPage, type AuditSessionRow } from "$lib/stores/audit.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";

  let rows = $state<AuditSessionRow[]>([]);
  let nextCursor = $state<string | null>(null);
  let endpointId = $state<string>("");
  // <input type="date"> gives a bare YYYY-MM-DD that the user picked in their
  // local calendar. We expand to local-day boundaries (00:00 / 23:59:59.999
  // local) and convert to UTC ISO instants so SQLite's text comparison on
  // ISO-8601 createdAt matches what the user sees on screen.
  let fromDate = $state<string>("");
  let toDate = $state<string>("");
  let loading = $state(false);

  const endpointLabel = $derived((id: string) => $endpoints.find((e) => e.id === id)?.label ?? id);

  onMount(() => {
    void load(true);
  });

  function localDayStart(yyyymmdd: string): string {
    const [y, m, d] = yyyymmdd.split("-").map(Number);
    return new Date(y, m - 1, d, 0, 0, 0, 0).toISOString();
  }
  function localDayEnd(yyyymmdd: string): string {
    const [y, m, d] = yyyymmdd.split("-").map(Number);
    return new Date(y, m - 1, d, 23, 59, 59, 999).toISOString();
  }

  async function load(reset: boolean) {
    if (loading) return;
    loading = true;
    try {
      const cursor = reset ? undefined : (nextCursor ?? undefined);
      const page = await fetchAuditPage(
        {
          endpointId: endpointId || undefined,
          from: fromDate ? localDayStart(fromDate) : undefined,
          to: toDate ? localDayEnd(toDate) : undefined,
        },
        cursor,
      );
      rows = reset ? page.rows : [...rows, ...page.rows];
      nextCursor = page.nextCursor;
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      loading = false;
    }
  }

  function onFilterChange() {
    void load(true);
  }

  function clearDates() {
    fromDate = "";
    toDate = "";
    void load(true);
  }

  function formatDuration(ms: number | null): string {
    if (ms === null) return "—";
    const s = Math.floor(ms / 1000);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    const rem = s % 60;
    if (m < 60) return `${m}m ${rem}s`;
    const h = Math.floor(m / 60);
    return `${h}h ${m % 60}m`;
  }

  function formatTimestamp(iso: string): string {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }
</script>

<div class="audit-page">
  <div class="audit-filter">
    <div class="filter-group">
      <label class="filter-label" for="endpoint-filter">Endpoint</label>
      <select id="endpoint-filter" bind:value={endpointId} onchange={onFilterChange}>
        <option value="">All endpoints</option>
        {#each $endpoints as ep (ep.id)}
          <option value={ep.id}>{ep.label}</option>
        {/each}
      </select>
    </div>
    <div class="filter-group">
      <label class="filter-label" for="from-filter">From</label>
      <input
        id="from-filter"
        type="date"
        bind:value={fromDate}
        max={toDate || undefined}
        onchange={onFilterChange}
      />
    </div>
    <div class="filter-group">
      <label class="filter-label" for="to-filter">To</label>
      <input
        id="to-filter"
        type="date"
        bind:value={toDate}
        min={fromDate || undefined}
        onchange={onFilterChange}
      />
    </div>
    {#if fromDate || toDate}
      <div class="filter-group">
        <span class="filter-label" aria-hidden="true">&nbsp;</span>
        <button type="button" class="btn btn-secondary btn-clear" onclick={clearDates}
          >Clear dates</button
        >
      </div>
    {/if}
  </div>

  <SettingsList empty={rows.length === 0 && !loading} emptyText="No audit entries">
    {#each rows as row (row.sessionId)}
      <SettingsRow detailLabel="Metadata">
        {#snippet primary()}
          <span class="row-label">
            <span class="status-dot {row.status}"></span>{endpointLabel(row.endpointId)}
          </span>
          <span class="badge badge-source">{row.source}</span>
          {#if row.closeReason}
            <span class="badge badge-reason">{row.closeReason}</span>
          {/if}
        {/snippet}
        {#snippet secondary()}
          {row.sessionId}<span class="row-dot">·</span>{formatTimestamp(row.createdAt)}<span
            class="row-dot">·</span
          >{formatDuration(row.durationMs)}
        {/snippet}
        {#snippet detailSlot()}
          <dl class="meta-grid">
            <dt>Status</dt>
            <dd>{row.status}{row.closedAt ? ` (closed ${formatTimestamp(row.closedAt)})` : ""}</dd>
            {#if row.sourceIp}
              <dt>Source IP</dt>
              <dd>{row.sourceIp}</dd>
            {/if}
            {#if row.mcpClientName}
              <dt>MCP client</dt>
              <dd>{row.mcpClientName}{row.mcpClientVersion ? ` ${row.mcpClientVersion}` : ""}</dd>
            {/if}
            {#if row.mcpReason}
              <dt>MCP reason</dt>
              <dd>{row.mcpReason}</dd>
            {/if}
            {#if row.clientHostname || row.clientOs || row.clientVersion}
              <dt>Agent</dt>
              <dd>
                {[row.clientHostname, row.clientOs, row.clientVersion].filter(Boolean).join(" · ")}
              </dd>
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
    min-width: 14rem;
  }

  .audit-filter input[type="date"] {
    font-family: var(--font-mono);
  }

  /* Don't stretch to the column width — natural button size. */
  .btn-clear {
    align-self: flex-start;
  }

  .row-label {
    font-weight: 600;
    font-size: var(--body-md);
    color: var(--on-surface);
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
  }

  .row-dot {
    color: var(--on-surface-faint);
    margin: 0 var(--space-2);
  }

  .badge-source {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--on-surface-variant);
  }

  .badge-reason {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    color: var(--on-surface-variant);
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
