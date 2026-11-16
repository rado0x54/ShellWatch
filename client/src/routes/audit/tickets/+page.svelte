<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<!--
  Audit → Tickets (#306): the life of every one-time access ticket of the
  account — minted, redeemed, attached, each admission attempt, admitted,
  ended (with the reason), revoked, expired. Reason and user agent are
  self-reported by the guest.
-->
<script lang="ts">
  import { onMount } from "svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";
  import { endpoints, fetchEndpoints } from "$lib/stores/endpoints.js";
  import {
    fetchTicketEvents,
    TICKET_EVENTS,
    type TicketEventRow,
  } from "$lib/stores/ticket-audit.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";

  let rows = $state<TicketEventRow[]>([]);
  let nextCursor = $state<string | null>(null);
  let loading = $state(false);
  let event = $state("");
  let ticketFilter = $state("");

  onMount(() => {
    void fetchEndpoints();
    void load(true);
  });

  // Each load gets a generation; only the latest one may write results. A
  // filter change (reset) always starts a new load and supersedes whatever is
  // in flight, so a slow response for an old filter can never land on top of
  // the new one. "Load more" is the only request dropped while loading.
  let generation = 0;

  async function load(reset: boolean) {
    if (loading && !reset) return;
    const gen = ++generation;
    loading = true;
    try {
      const page = await fetchTicketEvents(
        { event: event || undefined, ticketId: ticketFilter || undefined },
        reset ? undefined : (nextCursor ?? undefined),
      );
      if (gen !== generation) return;
      rows = reset ? page.rows : [...rows, ...page.rows];
      nextCursor = page.nextCursor;
    } catch (err) {
      if (gen === generation) toastError(errorMessage(err));
    } finally {
      if (gen === generation) loading = false;
    }
  }

  function applyFilters() {
    nextCursor = null;
    void load(true);
  }

  function pinTicket(id: string) {
    ticketFilter = id;
    applyFilters();
  }

  function endpointLabel(id: string): string {
    return $endpoints.find((e) => e.id === id)?.label ?? id;
  }

  function formatTimestamp(iso: string): string {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
  }

  function fmtDuration(ms: number): string {
    const s = Math.round(ms / 1000);
    return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
  }
</script>

<div class="audit-page">
  <div class="filters">
    <label>
      <span>Event</span>
      <select bind:value={event} onchange={applyFilters}>
        <option value="">All</option>
        {#each TICKET_EVENTS as ev (ev)}
          <option value={ev}>{ev}</option>
        {/each}
      </select>
    </label>
    {#if ticketFilter}
      <button
        type="button"
        class="btn btn-secondary"
        onclick={() => {
          ticketFilter = "";
          applyFilters();
        }}
      >
        Clear ticket filter
      </button>
    {/if}
  </div>

  <SettingsList empty={rows.length === 0 && !loading} emptyText="No ticket events recorded">
    {#each rows as row (row.id)}
      <SettingsRow detailLabel="Details">
        {#snippet primary()}
          <span class="row-label">{row.ticketLabel || "(no label)"}</span>
          <span class="badge badge-event">{row.event}</span>
          {#if row.endReason}
            <span class="badge">{row.endReason}</span>
          {/if}
        {/snippet}
        {#snippet secondary()}
          {formatTimestamp(row.createdAt)} · {endpointLabel(row.endpointId)}
          {#if row.sourceIp}· {row.sourceIp}{/if}
        {/snippet}
        {#snippet detailSlot()}
          <dl class="detail-grid">
            <dt>Ticket</dt>
            <dd><code>{row.ticketId}</code></dd>
            <dt>Options</dt>
            <dd>
              link valid {Math.round(row.redeemTtlSeconds / 60)} min · session
              {Math.round(row.lifetimeSeconds / 60)} min · reason
              {row.reasonRequired ? "required" : "optional"} · agent forwarding
              {row.agentForward ? "on" : "off"}
            </dd>
            {#if row.channel}
              <dt>Channel</dt>
              <dd>{row.channel}</dd>
            {/if}
            {#if row.reason}
              <dt>Reason (self-reported)</dt>
              <dd class="wrap">{row.reason}</dd>
            {/if}
            {#if row.userAgent}
              <dt>User agent (self-reported)</dt>
              <dd class="wrap"><code>{row.userAgent}</code></dd>
            {/if}
            {#if row.confirmationCode}
              <dt>Confirmation code</dt>
              <dd><code>{row.confirmationCode}</code></dd>
            {/if}
            {#if row.attempt}
              <dt>Attempt</dt>
              <dd>{row.attempt}</dd>
            {/if}
            {#if row.sessionId}
              <dt>Session</dt>
              <dd><code>{row.sessionId}</code></dd>
            {/if}
            {#if row.durationMs !== null}
              <dt>Duration</dt>
              <dd>{fmtDuration(row.durationMs)}</dd>
            {/if}
          </dl>
          {#if row.ticketId !== ticketFilter}
            <div class="detail-actions">
              <button
                type="button"
                class="btn btn-secondary"
                onclick={() => pinTicket(row.ticketId)}
              >
                Show this ticket's history
              </button>
            </div>
          {/if}
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
  .filters {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--space-4);
    margin-bottom: 1rem;
  }

  .filters label {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .filters label span {
    font-size: var(--label-md);
    color: var(--on-surface-variant);
  }

  .row-label {
    font-weight: 600;
    font-size: var(--body-md);
    color: var(--on-surface);
  }

  .badge-event {
    font-family: var(--font-mono);
  }

  .detail-grid {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-2) var(--space-4);
    margin: 0;
    font-size: var(--label-md);
  }

  .detail-grid dt {
    color: var(--on-surface-variant);
  }

  .detail-grid dd {
    margin: 0;
    color: var(--on-surface);
  }

  .wrap {
    overflow-wrap: anywhere;
  }

  .detail-actions {
    margin-top: var(--space-3);
  }

  .audit-footer {
    display: flex;
    justify-content: center;
    margin-top: 1rem;
  }

  .end-marker {
    color: var(--on-surface-variant);
    font-size: var(--label-md);
  }
</style>
