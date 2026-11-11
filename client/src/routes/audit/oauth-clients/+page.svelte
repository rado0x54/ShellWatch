<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<!--
  Audit → OAuth clients (#242): the admin-only registration log for DCR and
  CIMD. Unlike every other Audit tab this one is server-wide, not
  account-scoped — the rows are pre-account by nature — so a non-admin gets a
  403 and sees the explanation rather than an empty list.
-->
<script lang="ts">
  import { onMount } from "svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";
  import {
    fetchOAuthClients,
    displayIdentity,
    NotAdminError,
    type OAuthClientRegistration,
    type OAuthClientFilters,
  } from "$lib/stores/oauth-clients.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";

  let rows = $state<OAuthClientRegistration[]>([]);
  let nextCursor = $state<string | null>(null);
  let loading = $state(false);
  let forbidden = $state(false);
  let origin = $state("");
  let event = $state("");
  /** Set when a row's client_id is pinned, to show just that client's history. */
  let clientFilter = $state("");

  onMount(() => void load(true));

  async function load(reset: boolean) {
    if (loading) return;
    loading = true;
    try {
      const filters: OAuthClientFilters = {
        origin: origin || undefined,
        event: event || undefined,
        clientId: clientFilter || undefined,
      };
      const page = await fetchOAuthClients(filters, reset ? undefined : (nextCursor ?? undefined));
      rows = reset ? page.rows : [...rows, ...page.rows];
      nextCursor = page.nextCursor;
      forbidden = false;
    } catch (err) {
      if (err instanceof NotAdminError) {
        forbidden = true;
        rows = [];
        nextCursor = null;
      } else {
        toastError(errorMessage(err));
      }
    } finally {
      loading = false;
    }
  }

  function applyFilters() {
    nextCursor = null;
    void load(true);
  }

  function pinClient(clientId: string) {
    clientFilter = clientId;
    applyFilters();
  }

  function clearClient() {
    clientFilter = "";
    applyFilters();
  }

  function formatTimestamp(iso: string): string {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }
</script>

<div class="audit-page">
  {#if forbidden}
    <div class="forbidden">
      <h2>Admin role required</h2>
      <p>
        This log covers every OAuth client on the server, not just your own. Client registration
        happens before anyone signs in, so there is no account to scope it to — only an admin can
        read it.
      </p>
    </div>
  {:else}
    <div class="filters">
      <label>
        <span>Origin</span>
        <select bind:value={origin} onchange={applyFilters}>
          <option value="">All</option>
          <option value="cimd">CIMD</option>
          <option value="dcr">DCR</option>
        </select>
      </label>
      <label>
        <span>Event</span>
        <select bind:value={event} onchange={applyFilters}>
          <option value="">All</option>
          <option value="registered">Registered</option>
          <option value="refreshed">Refreshed</option>
          <option value="rejected">Rejected</option>
        </select>
      </label>
      {#if clientFilter}
        <button type="button" class="btn btn-secondary" onclick={clearClient}>
          Clear client filter
        </button>
      {/if}
    </div>

    {#if clientFilter}
      <p class="pinned">
        Showing one client: <code>{clientFilter}</code>
      </p>
    {/if}

    <SettingsList
      empty={rows.length === 0 && !loading}
      emptyText="No client registrations recorded"
    >
      {#each rows as row (row.id)}
        <SettingsRow detailLabel="Details">
          {#snippet primary()}
            <span class="row-label">
              <span class="event-dot {row.event}"></span>
              <span class="identity">{displayIdentity(row)}</span>
            </span>
            <span class="badge badge-origin {row.origin}">{row.origin.toUpperCase()}</span>
            <span class="badge badge-event">{row.event}</span>
          {/snippet}
          {#snippet secondary()}
            {formatTimestamp(row.createdAt)}
            {#if row.clientName && row.origin === "cimd"}
              · {row.clientName}
            {/if}
          {/snippet}
          {#snippet detailSlot()}
            <dl class="detail-grid">
              <dt>Client ID</dt>
              <dd><code class="wrap">{row.clientId || "— none (no client was created)"}</code></dd>
              {#if row.clientName}
                <dt>Name</dt>
                <dd>{row.clientName}</dd>
              {/if}
              {#if row.metadataHost}
                <dt>Document host</dt>
                <dd><code>{row.metadataHost}</code></dd>
              {/if}
              {#if row.authMethod}
                <dt>Auth method</dt>
                <dd><code>{row.authMethod}</code></dd>
              {/if}
              {#if row.scope}
                <dt>Scope</dt>
                <dd><code>{row.scope}</code></dd>
              {/if}
              {#if row.redirectUris.length > 0}
                <dt>Redirect URIs</dt>
                <dd>
                  {#each row.redirectUris as uri (uri)}
                    <code class="wrap block">{uri}</code>
                  {/each}
                </dd>
              {/if}
              {#if row.reason}
                <dt>Reason</dt>
                <dd class="reason">{row.reason}</dd>
              {/if}
              {#if row.sourceIp}
                <dt>Source IP</dt>
                <dd><code>{row.sourceIp}</code></dd>
              {/if}
            </dl>
            {#if row.clientId && row.clientId !== clientFilter}
              <div class="detail-actions">
                <button
                  type="button"
                  class="btn btn-secondary"
                  onclick={() => pinClient(row.clientId)}
                >
                  Show this client's history
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
  {/if}
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

  .pinned {
    font-size: var(--label-md);
    color: var(--on-surface-variant);
    margin-bottom: var(--space-3);
  }

  .row-label {
    font-weight: 600;
    font-size: var(--body-md);
    color: var(--on-surface);
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
  }

  .identity {
    font-family: var(--font-mono);
  }

  .event-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex: none;
    background: var(--on-surface-variant);
  }

  .event-dot.registered {
    background: var(--primary);
  }

  .event-dot.refreshed {
    background: rgb(255, 196, 0);
  }

  .event-dot.rejected {
    background: var(--error);
  }

  .badge-origin,
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

  .detail-grid code {
    font-family: var(--font-mono);
  }

  .wrap {
    overflow-wrap: anywhere;
  }

  .block {
    display: block;
  }

  .reason {
    overflow-wrap: anywhere;
  }

  .detail-actions {
    margin-top: var(--space-3);
  }

  .forbidden {
    border: 1px solid var(--outline-variant);
    background: var(--surface-container);
    padding: var(--space-5);
  }

  .forbidden h2 {
    font-size: var(--body-lg);
    font-weight: 600;
    margin: 0 0 var(--space-2);
  }

  .forbidden p {
    margin: 0;
    color: var(--on-surface-variant);
    font-size: var(--body-md);
    max-width: 60ch;
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
