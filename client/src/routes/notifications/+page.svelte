<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";
  import {
    fetchNotifications,
    notificationLink,
    type AppNotification,
  } from "$lib/stores/notifications.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";

  let rows = $state<AppNotification[]>([]);
  let nextCursor = $state<string | null>(null);
  let loading = $state(false);

  onMount(() => {
    void load(true);
  });

  async function load(reset: boolean) {
    if (loading) return;
    loading = true;
    try {
      const page = await fetchNotifications(reset ? undefined : (nextCursor ?? undefined));
      rows = reset ? page.rows : [...rows, ...page.rows];
      nextCursor = page.nextCursor;
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      loading = false;
    }
  }

  function formatTimestamp(iso: string): string {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }

  function followLink(href: string) {
    // Typed per-kind path (runtime string — same guard as the toast links).
    if (href.startsWith("/") && !href.startsWith("//")) {
      window.location.href = href;
    }
  }
</script>

<div class="notifications-page">
  <div class="page-header">
    <h1>Notifications</h1>
    <p class="subtitle">
      Server alerts you must not miss — newest first. Each entry was also pushed live to open tabs;
      this log is where a closed tab catches up.
    </p>
  </div>

  <SettingsList empty={rows.length === 0 && !loading} emptyText="No notifications">
    {#each rows as n (n.id)}
      <SettingsRow detailLabel={n.detail || n.payload ? "Details" : undefined}>
        {#snippet primary()}
          <span class="row-label">
            <span class="severity-dot {n.severity}"></span>{n.title}
          </span>
          <span class="badge badge-type">{n.type}</span>
        {/snippet}
        {#snippet secondary()}
          {formatTimestamp(n.createdAt)}
        {/snippet}
        {#snippet detailSlot()}
          {#if n.detail}
            <pre class="notification-detail">{n.detail}</pre>
          {/if}
          {#if notificationLink(n)}
            {@const link = notificationLink(n)!}
            <div class="detail-actions">
              <button type="button" class="btn btn-secondary" onclick={() => followLink(link.href)}>
                {link.label}
              </button>
            </div>
          {/if}
        {/snippet}
      </SettingsRow>
    {/each}
  </SettingsList>

  {#if nextCursor}
    <div class="load-more">
      <button
        type="button"
        class="btn btn-secondary"
        onclick={() => load(false)}
        disabled={loading}
      >
        {loading ? "Loading…" : "Load more"}
      </button>
    </div>
  {/if}
</div>

<style>
  .notifications-page {
    padding: 2rem;
    overflow-y: auto;
    height: 100%;
  }

  .page-header {
    margin-bottom: 1.5rem;
  }

  .page-header h1 {
    font-family: var(--font-display);
    font-size: var(--display-md);
    font-weight: 600;
    letter-spacing: -0.035em;
  }

  .subtitle {
    color: var(--on-surface-variant);
    font-size: var(--body-md);
    margin-top: var(--space-2);
  }

  .row-label {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
  }

  .severity-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex: none;
  }

  .severity-dot.info {
    background: var(--primary);
  }

  .severity-dot.warning {
    background: rgb(255, 196, 0);
  }

  .severity-dot.error {
    background: var(--error);
  }

  .badge-type {
    font-family: var(--font-mono);
  }

  .notification-detail {
    font-family: var(--font-mono);
    font-size: var(--label-md);
    color: var(--on-surface);
    background: var(--surface-container);
    border: 1px solid var(--outline-variant);
    padding: var(--space-3);
    margin: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .detail-actions {
    margin-top: var(--space-3);
  }

  .load-more {
    display: flex;
    justify-content: center;
    margin-top: 1rem;
  }

  @media (max-width: 768px) {
    .notifications-page {
      padding: 1rem;
    }
  }
</style>
