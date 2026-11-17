<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  // "Share access" for one endpoint (#306): choose the ticket's options (each
  // defaults to its most restrictive value), mint it, then hand the link over
  // (copy, QR code, navigator.share). Outstanding tickets and guest sessions
  // are managed on the Guest access page.
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import Modal from "$lib/components/Modal.svelte";
  import QrCode from "$lib/components/QrCode.svelte";
  import type { Endpoint } from "$lib/stores/endpoints.js";
  import {
    DEFAULT_MINT_OPTIONS,
    mintTicket,
    shareLink,
    type MintOptions,
  } from "$lib/stores/tickets.js";
  import { toastError, toastInfo } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import { formatEndpointAddress } from "$lib/utils/endpoint-address.js";

  interface Props {
    endpoint: Endpoint;
    onClose: () => void;
  }

  let { endpoint, onClose }: Props = $props();

  const REDEEM_TTL_CHOICES = [
    { s: 60, label: "1 minute" },
    { s: 300, label: "5 minutes" },
    { s: 900, label: "15 minutes" },
    { s: 3600, label: "1 hour" },
    { s: 8 * 3600, label: "8 hours" },
    { s: 86_400, label: "24 hours" },
  ];
  const LIFETIME_CHOICES = [
    { s: 60, label: "1 minute" },
    { s: 300, label: "5 minutes" },
    { s: 900, label: "15 minutes" },
    { s: 1800, label: "30 minutes" },
    { s: 3600, label: "1 hour" },
    { s: 2 * 3600, label: "2 hours" },
    { s: 4 * 3600, label: "4 hours" },
    { s: 8 * 3600, label: "8 hours" },
  ];

  let opts = $state<MintOptions>({ ...DEFAULT_MINT_OPTIONS });
  let busy = $state(false);
  let link = $state<string | null>(null);
  const canShare = typeof navigator !== "undefined" && typeof navigator.share === "function";

  async function handleMint(): Promise<void> {
    if (busy) return;
    busy = true;
    try {
      const { token } = await mintTicket(endpoint.id, opts);
      link = shareLink(token);
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      busy = false;
    }
  }

  async function copyLink(): Promise<void> {
    if (!link) return;
    try {
      await navigator.clipboard.writeText(link);
      toastInfo("Access link copied");
    } catch {
      toastError("Copy failed — select the link and copy it manually");
    }
  }

  async function shareViaSystem(): Promise<void> {
    if (!link) return;
    try {
      await navigator.share({ title: "ShellWatch access", url: link });
    } catch {
      // The user dismissed the share sheet.
    }
  }

  async function openGuestAccess(): Promise<void> {
    onClose();
    await goto(resolve("/guests"));
  }
</script>

<Modal title="Share access" {onClose} onSubmit={link ? undefined : handleMint} width="560px">
  <p class="modal-desc">
    <strong>{endpoint.label}</strong> ({formatEndpointAddress(endpoint)})
  </p>
  <p class="notice">
    A ticket grants a shell as <code>{endpoint.username}</code> on this host — not a sandbox. To really
    limit a guest, share an endpoint whose remote user is restricted on the host itself.
  </p>

  {#if !link}
    <div class="field">
      <label for="tk-label"
        >Label <span class="field-hint">(shown on the approval prompt)</span></label
      >
      <input id="tk-label" type="text" maxlength="100" bind:value={opts.label} />
    </div>
    <div class="field-row">
      <div class="field">
        <label for="tk-ttl">Link valid for</label>
        <select id="tk-ttl" bind:value={opts.redeemTtlSeconds}>
          {#each REDEEM_TTL_CHOICES as c (c.s)}
            <option value={c.s}>{c.label}</option>
          {/each}
        </select>
      </div>
      <div class="field">
        <label for="tk-life">Session ends after</label>
        <select id="tk-life" bind:value={opts.lifetimeSeconds}>
          {#each LIFETIME_CHOICES as c (c.s)}
            <option value={c.s}>{c.label}</option>
          {/each}
        </select>
      </div>
    </div>
    <label class="check">
      <input type="checkbox" bind:checked={opts.reasonRequired} />
      Guest must state a reason
    </label>
    <label class="check">
      <input type="checkbox" bind:checked={opts.agentForward} disabled={!endpoint.agentForward} />
      Agent forwarding
    </label>
    {#if !endpoint.agentForward}
      <p class="field-hint">Agent forwarding is off for this endpoint.</p>
    {:else if opts.agentForward}
      <p class="warning">
        Lets the guest trigger further sign requests from inside the session (each one still needs
        your approval).
      </p>
    {/if}
  {:else}
    <p>
      Send this link to the guest. It works once; you approve the guest on a device you are signed
      in on. Follow it under
      <button type="button" class="link-btn" onclick={openGuestAccess}>Guest access</button>.
    </p>
    <div class="share">
      <QrCode value={link} size={176} />
      <div class="share-actions">
        <input
          class="link"
          type="text"
          readonly
          value={link}
          onfocus={(e) => e.currentTarget.select()}
        />
        <button type="button" class="btn btn-primary" onclick={copyLink}>Copy link</button>
        {#if canShare}
          <button type="button" class="btn btn-secondary" onclick={shareViaSystem}>Share…</button>
        {/if}
      </div>
    </div>
  {/if}

  {#snippet actions()}
    <button type="button" class="btn btn-secondary" onclick={onClose}>Close</button>
    {#if !link}
      <button type="submit" class="btn btn-primary" disabled={busy}>
        {busy ? "Creating…" : "Create link"}
      </button>
    {:else}
      <button type="button" class="btn btn-secondary" onclick={() => (link = null)}>
        Create another
      </button>
    {/if}
  {/snippet}
</Modal>

<style>
  .notice {
    font-size: var(--label-md);
    color: var(--on-surface-variant);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    margin-bottom: var(--space-3);
    flex: 1;
  }

  .field-row {
    display: flex;
    gap: var(--space-4);
  }

  @media (max-width: 480px) {
    .field-row {
      flex-direction: column;
      gap: 0;
    }
  }

  .field-hint {
    color: var(--on-surface-variant);
    font-size: var(--label-md);
  }

  .check {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin-bottom: var(--space-2);
  }

  .warning {
    color: var(--warning, #f8a010);
    font-size: var(--label-md);
  }

  .share {
    display: flex;
    gap: var(--space-4);
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .share-actions {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    flex: 1;
    min-width: 200px;
  }

  .link {
    font-family: var(--font-mono);
    font-size: var(--label-md);
    width: 100%;
  }

  .link-btn {
    background: none;
    border: none;
    padding: 0;
    color: var(--primary);
    font: inherit;
    text-decoration: underline;
    cursor: pointer;
  }
</style>
