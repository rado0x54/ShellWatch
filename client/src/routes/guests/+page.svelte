<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<!--
  Guest access (#306): everything the owner has shared, in one place.
  - Active: guests who used their link: connecting, waiting for approval,
    refused (may ask again), connected. End access revokes the ticket.
  - Unused links: minted, not used yet. Revoke deletes the link.
  - Recently ended: kept by the server for 5 minutes (at most 10), with why
    it ended; they leave on their own. Audit → Tickets has the history.
  The list is the tickets store, refreshed on every tickets:changed.
-->
<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { SvelteSet } from "svelte/reactivity";
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import ConfirmDialog from "$lib/components/ConfirmDialog.svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";
  import { openConnectDialog } from "$lib/stores/connect-dialog.js";
  import { endpoints } from "$lib/stores/endpoints.js";
  import {
    endReasonLabel,
    fetchTickets,
    groupTickets,
    revokeTicket,
    tickets,
    ticketsClockOffset,
    type Ticket,
  } from "$lib/stores/tickets.js";
  import { toastError, toastInfo } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";

  // Deadlines are server times: count down against the server's clock.
  const serverNow = (): number => Date.now() + $ticketsClockOffset;
  let now = $state(Date.now());
  let ticker: ReturnType<typeof setInterval> | null = null;
  /** Tickets with a revoke in flight (each row on its own). */
  const busy = new SvelteSet<string>();
  let confirmEnd = $state<Ticket | null>(null);

  const groups = $derived(groupTickets($tickets));

  onMount(() => {
    void fetchTickets().catch(() => {});
    now = serverNow();
    ticker = setInterval(() => (now = serverNow()), 1000);
  });

  onDestroy(() => {
    if (ticker) clearInterval(ticker);
  });

  function endpointLabel(id: string): string {
    return $endpoints.find((e) => e.id === id)?.label ?? id;
  }

  /** "4:05" until a deadline; "0:00" once it passed. */
  function remaining(deadline: string | null): string {
    if (!deadline) return "—";
    const s = Math.max(0, Math.ceil((Date.parse(deadline) - now) / 1000));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = String(s % 60).padStart(2, "0");
    return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${sec}` : `${m}:${sec}`;
  }

  function time(iso: string | null): string {
    if (!iso) return "—";
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString();
  }

  function minutes(seconds: number): string {
    return seconds % 3600 === 0 ? `${seconds / 3600} h` : `${Math.round(seconds / 60)} min`;
  }

  /** What the active row's state badge says, and its colour. */
  function activeState(t: Ticket): { label: string; cls: string } {
    switch (t.state) {
      case "redeemed":
        return { label: "connecting", cls: "badge-pending" };
      case "pending":
        return { label: "waiting for approval", cls: "badge-pending" };
      case "refused":
        return { label: "not admitted", cls: "badge-unavailable" };
      case "open":
        return t.guest?.attached
          ? { label: "connected", cls: "badge-available" }
          : { label: "away", cls: "badge-pending" };
      default:
        return { label: t.state, cls: "" };
    }
  }

  /** The deadline that matters for an active guest, for the secondary line. */
  function activeDeadline(t: Ticket): string {
    const g = t.guest;
    if (!g) return "";
    if (t.state === "open") return `ends in ${remaining(g.lifetimeDeadline)}`;
    if (g.admissionDeadline) return `admission closes in ${remaining(g.admissionDeadline)}`;
    return ""; // not attached yet: the state badge says so
  }

  async function revoke(t: Ticket, done: string): Promise<void> {
    if (busy.has(t.id)) return;
    busy.add(t.id);
    try {
      const result = await revokeTicket(t.id);
      // "ended": it ended (or expired) on its own meanwhile; nothing changed.
      toastInfo(result === "revoked" ? done : "Already ended");
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      busy.delete(t.id);
      if (confirmEnd?.id === t.id) confirmEnd = null;
    }
  }

  async function view(sessionId: string): Promise<void> {
    await goto(resolve("/session/[id]", { id: sessionId }));
  }
</script>

<div class="guests-page">
  <header class="guests-header">
    <div>
      <h1>Guest access</h1>
      <p class="subtitle">
        One-time access you shared. Ended sessions stay here for 5 minutes; the full history is
        under Audit → Tickets.
      </p>
    </div>
    <button type="button" class="btn btn-primary" onclick={() => openConnectDialog("share")}>
      Share access
    </button>
  </header>

  <section>
    <h2>Active</h2>
    <SettingsList empty={groups.active.length === 0} emptyText="No guests right now">
      {#each groups.active as t (t.id)}
        {@const st = activeState(t)}
        <SettingsRow detailLabel="Details">
          {#snippet primary()}
            <span class="row-label">{t.label || "(no label)"}</span>
            <span class="row-endpoint">{endpointLabel(t.endpointId)}</span>
            <span class="badge {st.cls}">{st.label}</span>
          {/snippet}
          {#snippet secondary()}
            {#if t.guest}
              code <span class="code">{t.guest.confirmationCode}</span><span class="sep">·</span>{t
                .guest.sourceIp}
              {#if activeDeadline(t)}<span class="sep">·</span>{activeDeadline(t)}{/if}
              {#if t.guest.reason}<br />“{t.guest.reason}”{/if}
            {/if}
          {/snippet}
          {#snippet detailSlot()}
            {@render details(t)}
          {/snippet}
          {#snippet actions()}
            {#if t.state === "open" && t.guest?.sessionId}
              {@const sid = t.guest.sessionId}
              <button type="button" class="btn btn-secondary" onclick={() => view(sid)}>
                View
              </button>
            {/if}
            <button
              type="button"
              class="btn btn-warn"
              disabled={busy.has(t.id)}
              onclick={() => (confirmEnd = t)}
            >
              End access
            </button>
          {/snippet}
        </SettingsRow>
      {/each}
    </SettingsList>
  </section>

  <section>
    <h2>Unused links</h2>
    <SettingsList empty={groups.invites.length === 0} emptyText="No unused links">
      {#each groups.invites as t (t.id)}
        <SettingsRow detailLabel="Details">
          {#snippet primary()}
            <span class="row-label">{t.label || "(no label)"}</span>
            <span class="row-endpoint">{endpointLabel(t.endpointId)}</span>
          {/snippet}
          {#snippet secondary()}
            expires in {remaining(t.expiresAt)} · created {time(t.createdAt)}
          {/snippet}
          {#snippet detailSlot()}
            {@render details(t)}
          {/snippet}
          {#snippet actions()}
            <button
              type="button"
              class="btn btn-secondary"
              disabled={busy.has(t.id)}
              onclick={() => revoke(t, "Link revoked")}
            >
              Revoke
            </button>
          {/snippet}
        </SettingsRow>
      {/each}
    </SettingsList>
  </section>

  <section>
    <h2>Recently ended</h2>
    <SettingsList empty={groups.ended.length === 0} emptyText="Nothing ended recently">
      {#each groups.ended as t (t.id)}
        <SettingsRow detailLabel="Details">
          {#snippet primary()}
            <span class="row-label">{t.label || "(no label)"}</span>
            <span class="row-endpoint">{endpointLabel(t.endpointId)}</span>
            <span class="badge">{endReasonLabel(t.endReason)}</span>
          {/snippet}
          {#snippet secondary()}
            ended {time(t.endedAt)}
            {#if t.guest}
              <span class="sep">·</span>code
              <span class="code">{t.guest.confirmationCode}</span><span class="sep">·</span>{t.guest
                .sourceIp}
            {/if}
          {/snippet}
          {#snippet detailSlot()}
            {@render details(t)}
          {/snippet}
        </SettingsRow>
      {/each}
    </SettingsList>
  </section>
</div>

{#snippet details(t: Ticket)}
  <dl class="detail-grid">
    <dt>Endpoint</dt>
    <dd>{endpointLabel(t.endpointId)}</dd>
    {#if t.guest}
      <dt>Code</dt>
      <dd class="code">{t.guest.confirmationCode}</dd>
      <dt>Reason</dt>
      <dd>{t.guest.reason || "—"} <span class="muted">(stated by the guest)</span></dd>
      <dt>From</dt>
      <dd>{t.guest.sourceIp}</dd>
      <dt>Browser</dt>
      <dd>{t.guest.userAgent || "—"} <span class="muted">(reported by the guest)</span></dd>
      <dt>Used</dt>
      <dd>{time(t.guest.redeemedAt)}</dd>
      <dt>Attempts</dt>
      <dd>{t.guest.attempt}</dd>
      {#if t.state !== "closed"}
        <dt>Connections</dt>
        <dd>{t.guest.connections}</dd>
      {/if}
      {#if t.guest.sessionId}
        <dt>Session</dt>
        <dd><code>{t.guest.sessionId}</code></dd>
      {/if}
    {/if}
    {#if t.endedAt}
      <dt>Ended</dt>
      <dd>{time(t.endedAt)} — {endReasonLabel(t.endReason)}</dd>
    {/if}
    <dt>Created</dt>
    <dd>{time(t.createdAt)}</dd>
    <dt>Options</dt>
    <dd>
      link valid {minutes(t.redeemTtlSeconds)} · session {minutes(t.lifetimeSeconds)} · reason
      {t.reasonRequired ? "required" : "optional"} · agent forwarding {t.agentForward
        ? "on"
        : "off"}
    </dd>
    <dt>Ticket</dt>
    <dd><code>{t.id}</code></dd>
  </dl>
{/snippet}

{#if confirmEnd}
  {@const target = confirmEnd}
  <ConfirmDialog
    title="End guest access?"
    confirmLabel="End access"
    processing={busy.has(target.id)}
    onConfirm={() => revoke(target, "Guest access ended")}
    onCancel={() => (confirmEnd = null)}
  >
    <p>
      This revokes the link for <strong>{target.label || endpointLabel(target.endpointId)}</strong>.
      {#if target.state === "open"}
        The guest's terminal session closes now.
      {:else}
        The guest can no longer be admitted.
      {/if}
    </p>
  </ConfirmDialog>
{/if}

<style>
  .guests-page {
    padding: 2rem;
    overflow-y: auto;
    height: 100%;
  }

  .guests-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-4);
    margin-bottom: 1.5rem;
  }

  .guests-header h1 {
    font-family: var(--font-display);
    font-size: var(--display-md);
    font-weight: 600;
    letter-spacing: -0.035em;
  }

  .subtitle {
    color: var(--on-surface-variant);
    font-size: var(--body-md);
    margin-top: var(--space-2);
    max-width: 60ch;
  }

  .guests-header > .btn {
    flex-shrink: 0;
  }

  section + section {
    margin-top: var(--space-6, 2rem);
  }

  section h2 {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--on-surface-variant);
    margin-bottom: var(--space-3);
  }

  .row-label {
    font-weight: 600;
    font-size: var(--body-md);
    color: var(--on-surface);
  }

  .row-endpoint {
    color: var(--on-surface-variant);
    font-size: var(--body-md);
  }

  .code {
    font-family: var(--font-mono);
    letter-spacing: 0.15em;
    color: var(--primary);
  }

  /* Separator between the secondary line's parts. */
  .sep {
    margin: 0 0.5ch;
  }

  .muted {
    color: var(--on-surface-faint);
  }

  .detail-grid {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-2) var(--space-4);
    margin: 0;
    font-size: var(--label-md);
    white-space: normal;
  }

  .detail-grid dt {
    color: var(--on-surface-variant);
  }

  .detail-grid dd {
    margin: 0;
    color: var(--on-surface);
    overflow-wrap: anywhere;
  }

  @media (max-width: 768px) {
    .guests-page {
      padding: 1rem;
    }

    .guests-header {
      flex-direction: column;
      align-items: stretch;
    }
  }

  /* Phones: label/value pairs stack instead of squeezing two columns. */
  @media (max-width: 480px) {
    .detail-grid {
      grid-template-columns: 1fr;
      gap: var(--space-1);
    }

    .detail-grid dd {
      margin-bottom: var(--space-2);
    }
  }
</style>
