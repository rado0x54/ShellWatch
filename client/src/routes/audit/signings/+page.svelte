<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";
  import {
    fetchSigningsPage,
    type SigningRequestRow,
    type SigningsFilters,
  } from "$lib/stores/audit.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";

  let rows = $state<SigningRequestRow[]>([]);
  let nextCursor = $state<string | null>(null);
  let source = $state<string>("");
  let outcome = $state<string>("");
  let fromDate = $state<string>("");
  let toDate = $state<string>("");
  let loading = $state(false);

  const hasAnyFilter = $derived(!!(source || outcome || fromDate || toDate));

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

  function buildFilters(): SigningsFilters {
    return {
      source: source || undefined,
      outcome: outcome || undefined,
      from: fromDate ? localDayStart(fromDate) : undefined,
      to: toDate ? localDayEnd(toDate) : undefined,
    };
  }

  async function load(reset: boolean) {
    if (loading) return;
    loading = true;
    try {
      const cursor = reset ? undefined : (nextCursor ?? undefined);
      const result = await fetchSigningsPage(buildFilters(), cursor);
      rows = reset ? result.rows : [...rows, ...result.rows];
      nextCursor = result.nextCursor;
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      loading = false;
    }
  }

  function onFilterChange() {
    void load(true);
  }

  function clearAll() {
    source = "";
    outcome = "";
    fromDate = "";
    toDate = "";
    void load(true);
  }

  function formatTimestamp(iso: string | null): string {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }

  function formatLatency(ms: number | null): string {
    if (ms === null) return "—";
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }

  function describeOriginatingActor(row: SigningRequestRow): string {
    if (row.source === "agent-proxy") {
      return [row.clientHostname, row.sourceIp].filter(Boolean).join(" · ") || "—";
    }
    if (row.source === "endpoint-auth") {
      if (row.mcpClientName) {
        return [row.mcpClientName, row.sourceIp].filter(Boolean).join(" · ") || "—";
      }
      return row.sourceIp ?? "UI";
    }
    if (row.source === "agent-forwarding") {
      return row.endpointLabel ?? row.endpointAddress ?? "—";
    }
    return "—";
  }

  function actionTarget(row: SigningRequestRow): string {
    if (row.type === "webauthn-sign") return row.passkeyLabel ?? row.credentialId ?? "passkey";
    return row.keyLabel ?? row.keyFingerprint ?? "key";
  }
</script>

<div class="audit-page">
  <div class="audit-filter">
    <div class="filter-group">
      <label class="filter-label" for="source-filter">Source</label>
      <select id="source-filter" bind:value={source} onchange={onFilterChange}>
        <option value="">All sources</option>
        <option value="endpoint-auth">Endpoint auth</option>
        <option value="agent-forwarding">Agent forwarding</option>
        <option value="agent-proxy">Agent proxy</option>
      </select>
    </div>
    <div class="filter-group">
      <label class="filter-label" for="outcome-filter">Outcome</label>
      <select id="outcome-filter" bind:value={outcome} onchange={onFilterChange}>
        <option value="">All outcomes</option>
        <option value="approved">Approved</option>
        <option value="denied">Denied</option>
        <option value="expired">Expired</option>
        <option value="cancelled">Cancelled</option>
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
    {#if hasAnyFilter}
      <div class="filter-group">
        <span class="filter-label" aria-hidden="true">&nbsp;</span>
        <button type="button" class="btn btn-secondary btn-clear" onclick={clearAll}
          >Clear filters</button
        >
      </div>
    {/if}
  </div>

  <SettingsList empty={rows.length === 0 && !loading} emptyText="No signing requests recorded">
    {#each rows as row (row.id)}
      <SettingsRow detailLabel="Metadata">
        {#snippet primary()}
          <span class="row-label">
            <span class="status-dot {row.outcome ?? 'pending'}"></span>{actionTarget(row)}
          </span>
          <span class="badge badge-type">{row.type}</span>
          <span class="badge badge-source">{row.source}</span>
          {#if row.outcome}
            <span class="badge badge-outcome badge-outcome-{row.outcome}">{row.outcome}</span>
          {:else}
            <span class="badge badge-outcome badge-outcome-pending">pending</span>
          {/if}
        {/snippet}
        {#snippet secondary()}
          {describeOriginatingActor(row)}<span class="row-dot">·</span>{formatTimestamp(
            row.createdAt,
          )}<span class="row-dot">·</span>{formatLatency(row.latencyMs)}
        {/snippet}
        {#snippet detailSlot()}
          <dl class="meta-grid">
            <dt>ID</dt>
            <dd>{row.id}</dd>
            <dt>Created</dt>
            <dd>{formatTimestamp(row.createdAt)}</dd>
            {#if row.resolvedAt}
              <dt>Resolved</dt>
              <dd>{formatTimestamp(row.resolvedAt)} ({formatLatency(row.latencyMs)})</dd>
            {/if}
            {#if row.cancelReason}
              <dt>Cancel reason</dt>
              <dd>{row.cancelReason}</dd>
            {/if}
            {#if row.endpointLabel || row.endpointAddress}
              <dt>Endpoint</dt>
              <dd>
                {row.endpointLabel ?? "—"}{row.endpointAddress ? ` (${row.endpointAddress})` : ""}
              </dd>
            {/if}
            {#if row.sessionId}
              <dt>Session</dt>
              <dd><code>{row.sessionId}</code></dd>
            {/if}
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
              <dt>Agent client</dt>
              <dd>
                {[row.clientHostname, row.clientOs, row.clientVersion].filter(Boolean).join(" · ")}
              </dd>
            {/if}
            {#if row.type === "webauthn-sign"}
              {#if row.credentialId}
                <dt>Credential</dt>
                <dd><code>{row.credentialId}</code></dd>
              {/if}
              {#if row.passkeyLabel}
                <dt>Passkey</dt>
                <dd>{row.passkeyLabel}</dd>
              {/if}
              {#if row.userVerification}
                <dt>User verification</dt>
                <dd>{row.userVerification}</dd>
              {/if}
            {:else if row.type === "key-approve"}
              {#if row.keyLabel}
                <dt>Key</dt>
                <dd>{row.keyLabel}</dd>
              {/if}
              {#if row.keyFingerprint}
                <dt>Fingerprint</dt>
                <dd><code>{row.keyFingerprint}</code></dd>
              {/if}
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
    min-width: 12rem;
  }

  .audit-filter input[type="date"] {
    font-family: var(--font-mono);
  }

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

  .badge-source,
  .badge-type,
  .badge-outcome {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--on-surface-variant);
  }

  .badge-outcome-approved {
    color: var(--success, var(--on-surface));
  }

  .badge-outcome-denied,
  .badge-outcome-cancelled {
    color: var(--error, var(--on-surface));
  }

  .badge-outcome-expired {
    color: var(--warning, var(--on-surface-faint));
  }

  .badge-outcome-pending {
    color: var(--on-surface-faint);
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
