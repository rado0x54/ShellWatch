<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import {
    authSessions,
    fetchAuthSessions,
    revokeAllAuthSessions,
    revokeAuthSession,
    type AuthSession,
  } from "$lib/stores/auth-sessions.js";
  import { toastError, toastInfo } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import ConfirmDialog from "$lib/components/ConfirmDialog.svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";

  let loading = $state(true);
  let processing = $state(false);
  let revokeTarget = $state<AuthSession | null>(null);
  let showRevokeAll = $state(false);

  onMount(async () => {
    try {
      await fetchAuthSessions();
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      loading = false;
    }
  });

  function formatWhen(iso: string | null): string {
    if (!iso) return "—";
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
  }

  async function confirmRevoke() {
    if (!revokeTarget) return;
    const target = revokeTarget;
    processing = true;
    try {
      // Invalidating the current (web UI) client signs this browser out —
      // revokeAuthSession redirects via logout(), so no toast in that case.
      await revokeAuthSession(target.clientId, target.current);
      if (!target.current) toastInfo(`Invalidated sessions for ${target.clientName}`);
      revokeTarget = null;
    } catch (err) {
      // A cancelled passkey prompt throws NotAllowedError — treat as a no-op.
      if ((err as Error)?.name !== "NotAllowedError") {
        toastError(errorMessage(err));
      }
    } finally {
      processing = false;
    }
  }

  async function confirmRevokeAll() {
    processing = true;
    try {
      await revokeAllAuthSessions(); // redirects via logout() on success
    } catch (err) {
      if ((err as Error)?.name !== "NotAllowedError") {
        toastError(errorMessage(err));
      }
      processing = false;
      showRevokeAll = false;
    }
  }
</script>

<section>
  <h2>Clients</h2>
  <p class="section-desc">
    Clients you've authorized to access your account, including this web app. "Invalidate sessions"
    kills that client's active tokens for your account (it must sign in again); invalidating the web
    app — or all sessions — signs you out here too.
  </p>

  {#if loading}
    <p class="muted">Loading…</p>
  {:else}
    <SettingsList empty={$authSessions.length === 0} emptyText="No connected clients.">
      {#each $authSessions as session (session.clientId)}
        <SettingsRow>
          {#snippet primary()}
            <span class="client-name">{session.clientName}</span>
            {#if session.current}
              <span class="badge-current">This app</span>
            {/if}
            <span class="client-id">{session.clientId}</span>
          {/snippet}
          {#snippet secondary()}
            <span class="scopes">
              {#each session.scopes as scope (scope)}
                <span class="scope">{scope}</span>
              {/each}
            </span>
            <span class="when">Last session authorization: {formatWhen(session.authorizedAt)}</span>
          {/snippet}
          {#snippet actions()}
            <button
              type="button"
              class="btn btn-secondary"
              disabled={processing}
              onclick={() => (revokeTarget = session)}
            >
              Invalidate Sessions
            </button>
          {/snippet}
        </SettingsRow>
      {/each}
    </SettingsList>

    {#if $authSessions.length > 0}
      <div class="actions-section">
        <button
          type="button"
          class="btn btn-secondary"
          disabled={processing}
          onclick={() => (showRevokeAll = true)}
        >
          Invalidate all sessions
        </button>
      </div>
    {/if}
  {/if}
</section>

{#if revokeTarget}
  <ConfirmDialog
    title="Invalidate sessions"
    confirmLabel="Invalidate"
    {processing}
    onConfirm={confirmRevoke}
    onCancel={() => (revokeTarget = null)}
  >
    <p>
      Invalidate all active sessions for <strong>{revokeTarget.clientName}</strong>?
      {#if revokeTarget.current}
        This is the app you're using now — you'll be signed out and returned to login.
      {:else}
        It will lose access and must sign in again.
      {/if}
      You'll confirm with your passkey.
    </p>
  </ConfirmDialog>
{/if}

{#if showRevokeAll}
  <ConfirmDialog
    title="Invalidate all sessions"
    confirmLabel="Invalidate all"
    {processing}
    onConfirm={confirmRevokeAll}
    onCancel={() => (showRevokeAll = false)}
  >
    <p>
      Invalidate <strong>all</strong> active sessions across every client and device, including this one.
      You'll be signed out and returned to login, and confirm with your passkey.
    </p>
  </ConfirmDialog>
{/if}

<style>
  h2 {
    font-size: 0.75rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .section-desc {
    margin: 0 0 var(--space-5);
    color: var(--on-surface-variant);
    font-size: var(--body-md);
  }

  .actions-section {
    margin-top: var(--space-5);
    display: flex;
    align-items: center;
    gap: var(--space-3);
    flex-wrap: wrap;
  }

  .client-name {
    font-weight: 600;
  }

  .badge-current {
    margin-left: var(--space-3);
    background: var(--surface-container-high);
    color: var(--primary);
    border-radius: 4px;
    padding: 0.1rem 0.4rem;
    font-size: var(--label-sm);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  .client-id {
    margin-left: var(--space-3);
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    color: var(--on-surface-faint);
  }

  .scopes {
    display: inline-flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin-right: var(--space-3);
  }

  .scope {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    background: var(--surface-container);
    border: 1px solid var(--outline-variant);
    border-radius: 4px;
    padding: 0.05rem 0.35rem;
    color: var(--on-surface-variant);
  }

  .when {
    color: var(--on-surface-faint);
    font-size: var(--label-sm);
  }

  .muted {
    color: var(--on-surface-variant);
  }
</style>
