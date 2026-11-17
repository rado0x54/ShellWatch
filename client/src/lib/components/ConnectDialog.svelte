<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  // The endpoint picker (sidebar "Connect", guest-access "Share access"):
  // every endpoint of the account, filterable, each with Connect and/or Share
  // access. Share access hands over to ShareTicketDialog for that endpoint.
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import Modal from "$lib/components/Modal.svelte";
  import ShareTicketDialog from "$lib/components/ShareTicketDialog.svelte";
  import { ApiError } from "$lib/api.js";
  import { get } from "svelte/store";
  import { page } from "$app/state";
  import {
    connectDialog,
    connectDialogSharing,
    type ConnectDialogMode,
  } from "$lib/stores/connect-dialog.js";
  import { endpoints, type Endpoint } from "$lib/stores/endpoints.js";
  import { createSession } from "$lib/stores/sessions-api.js";
  import { toastInfo, toastRequestError } from "$lib/stores/toasts.js";
  import { formatEndpointAddress } from "$lib/utils/endpoint-address.js";
  import { errorMessage } from "$lib/utils/error-message.js";

  interface Props {
    mode: ConnectDialogMode;
    onClose: () => void;
  }

  let { mode, onClose }: Props = $props();

  let query = $state("");
  let shareTarget = $state<Endpoint | null>(null);

  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return $endpoints;
    return $endpoints.filter((ep) =>
      [ep.label, formatEndpointAddress(ep), ep.description ?? ""].some((f) =>
        f.toLowerCase().includes(q),
      ),
    );
  });

  // The picker closes as soon as Connect is clicked: the request can wait on
  // the owner's own approval (a sign prompt, possibly on /sign), and the
  // session already shows as "opening" in the sidebar. The outcome arrives as
  // a navigation to the session or as an error toast, like any connect.
  // The jump to the new session only happens while it is still what the
  // user is waiting for: same page as the click, no dialog opened since.
  // Otherwise (they moved on, e.g. to approve on /sign, or opened the picker
  // again) the session just appears in the sidebar, with a toast.
  async function handleConnect(ep: Endpoint): Promise<void> {
    const from = page.url.pathname;
    onClose();
    try {
      const session = await createSession(ep.id);
      if (page.url.pathname === from && get(connectDialog) === null) {
        await goto(resolve("/session/[id]", { id: session.sessionId }));
      } else {
        toastInfo(`Session to ${ep.label} is ready — open it from the sidebar`);
      }
    } catch (err) {
      // A failure the server also published as a notification (#252) dedupes
      // against the pushed toast by id.
      toastRequestError(
        `Failed to create session: ${errorMessage(err)}`,
        err instanceof ApiError ? err.notificationId : undefined,
      );
    }
  }

  // Tell the layout not to close the dialog on a page change while the share
  // form (and possibly a one-time link) is on screen.
  $effect(() => {
    connectDialogSharing.set(shareTarget !== null);
    return () => connectDialogSharing.set(false);
  });

  /** Enter in the filter connects (or shares) when exactly one matches. */
  function handleSubmit(): void {
    if (filtered.length !== 1) return;
    if (mode === "connect") void handleConnect(filtered[0]);
    else shareTarget = filtered[0];
  }
</script>

{#if shareTarget}
  <ShareTicketDialog endpoint={shareTarget} {onClose} />
{:else}
  <Modal
    title={mode === "connect" ? "Connect" : "Share access"}
    {onClose}
    onSubmit={handleSubmit}
    width="560px"
  >
    {#if mode === "share"}
      <p class="modal-desc">Choose the endpoint a guest gets one-time access to.</p>
    {/if}
    <input
      class="filter"
      type="search"
      placeholder="Filter endpoints"
      aria-label="Filter endpoints"
      autocomplete="off"
      bind:value={query}
    />

    {#if $endpoints.length === 0}
      <p class="empty">No endpoints yet. Add one under Settings → Endpoints.</p>
    {:else if filtered.length === 0}
      <p class="empty">No endpoint matches “{query.trim()}”.</p>
    {:else}
      <ul class="endpoint-list">
        {#each filtered as ep (ep.id)}
          <li class="endpoint-row">
            <div class="endpoint-info">
              <span class="endpoint-label">
                {ep.label}
                {#if ep.isDemo}
                  <span class="badge badge-demo" title="Operator-curated demo endpoint">demo</span>
                {/if}
              </span>
              <span class="endpoint-address">{formatEndpointAddress(ep)}</span>
            </div>
            <div class="endpoint-actions">
              <button
                type="button"
                class="btn"
                class:btn-primary={mode === "share"}
                class:btn-secondary={mode === "connect"}
                onclick={() => (shareTarget = ep)}
              >
                Share access
              </button>
              {#if mode === "connect"}
                <button type="button" class="btn btn-primary" onclick={() => handleConnect(ep)}>
                  Connect
                </button>
              {/if}
            </div>
          </li>
        {/each}
      </ul>
    {/if}

    {#snippet actions()}
      <button type="button" class="btn btn-secondary" onclick={onClose}>Close</button>
    {/snippet}
  </Modal>
{/if}

<style>
  .filter {
    width: 100%;
    margin-bottom: var(--space-3);
  }

  .empty {
    color: var(--on-surface-variant);
    font-size: var(--body-md);
    padding: var(--space-4) 0;
  }

  .endpoint-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    /* The list scrolls inside the dialog; the filter and actions stay put. */
    max-height: min(60vh, 28rem);
    overflow-y: auto;
  }

  .endpoint-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    background: var(--surface-container-low);
  }

  .endpoint-info {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
    flex: 1;
  }

  .endpoint-label {
    font-weight: 600;
    font-size: var(--body-md);
    color: var(--on-surface);
    overflow-wrap: anywhere;
  }

  .endpoint-address {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    color: var(--on-surface-variant);
    overflow-wrap: anywhere;
  }

  .endpoint-actions {
    display: flex;
    gap: var(--space-2);
    flex-shrink: 0;
  }

  /* Phones: the buttons move under the label and share the row's width. */
  @media (max-width: 480px) {
    .endpoint-row {
      flex-direction: column;
      align-items: stretch;
    }

    .endpoint-actions > :global(.btn) {
      flex: 1;
    }
  }
</style>
