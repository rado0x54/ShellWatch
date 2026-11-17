<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  // "Share access" for one endpoint (#306): choose the ticket's options (each
  // defaults to its most restrictive value, the label to a readable name),
  // mint it, then hand the link over (QR code, copy, navigator.share).
  // Outstanding tickets and guest sessions are on the Guest access page.
  import Modal from "$lib/components/Modal.svelte";
  import QrCode from "$lib/components/QrCode.svelte";
  import type { Endpoint } from "$lib/stores/endpoints.js";
  import { DEFAULT_MINT_OPTIONS, mintTicket, type MintOptions } from "$lib/stores/tickets.js";
  import { toastError, toastInfo } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import { formatEndpointAddress } from "$lib/utils/endpoint-address.js";

  interface Props {
    endpoint: Endpoint;
    onClose: () => void;
  }

  let { endpoint, onClose }: Props = $props();

  const LABEL_MAX = 100;

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

  // The default label is taken once, when the dialog opens.
  // svelte-ignore state_referenced_locally
  let opts = $state<MintOptions>({
    ...DEFAULT_MINT_OPTIONS,
    label: `Guest access for ${endpoint.label}`.slice(0, LABEL_MAX),
  });
  let busy = $state(false);
  let link = $state<string | null>(null);
  const canShare = typeof navigator !== "undefined" && typeof navigator.share === "function";

  async function handleMint(): Promise<void> {
    if (busy) return;
    busy = true;
    try {
      link = (await mintTicket(endpoint.id, opts)).shareLink;
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
</script>

<Modal title="Share access" {onClose} onSubmit={link ? undefined : handleMint} width="560px">
  <p class="modal-desc">
    <strong>{endpoint.label}</strong> ({formatEndpointAddress(endpoint)})
  </p>

  {#if !link}
    <p class="note">
      A ticket grants a shell as <code>{endpoint.username}</code> on this host — not a sandbox. To really
      limit a guest, share an endpoint whose remote user is restricted on the host itself.
    </p>

    <div class="options">
      <label for="tk-label">Label</label>
      <input id="tk-label" type="text" maxlength={LABEL_MAX} bind:value={opts.label} />
      <span class="hint">Shown on the approval prompt.</span>

      <label for="tk-ttl">Link valid for</label>
      <select id="tk-ttl" bind:value={opts.redeemTtlSeconds}>
        {#each REDEEM_TTL_CHOICES as c (c.s)}
          <option value={c.s}>{c.label}</option>
        {/each}
      </select>

      <label for="tk-life">Session ends after</label>
      <select id="tk-life" bind:value={opts.lifetimeSeconds}>
        {#each LIFETIME_CHOICES as c (c.s)}
          <option value={c.s}>{c.label}</option>
        {/each}
      </select>

      <label for="tk-reason">Guest must state a reason</label>
      <input id="tk-reason" class="check" type="checkbox" bind:checked={opts.reasonRequired} />

      <label for="tk-forward">Agent forwarding</label>
      <input
        id="tk-forward"
        class="check"
        type="checkbox"
        bind:checked={opts.agentForward}
        disabled={!endpoint.agentForward}
      />
      {#if !endpoint.agentForward}
        <span class="hint">Agent forwarding is off for this endpoint.</span>
      {:else if opts.agentForward}
        <span class="hint warning">
          Lets the guest trigger further sign requests from inside the session (each one still needs
          your approval).
        </span>
      {/if}
    </div>
  {:else}
    <p class="note">
      Send this link to the guest. It works once; you approve the guest on a device you are signed
      in on.
    </p>
    <div class="share">
      <QrCode value={link} size={176} />
      <div class="link-field">
        <input
          class="link"
          type="text"
          readonly
          aria-label="Access link"
          value={link}
          onfocus={(e) => e.currentTarget.select()}
        />
        <button
          type="button"
          class="copy-btn"
          onclick={copyLink}
          title="Copy link"
          aria-label="Copy link"
        >
          <svg
            viewBox="0 0 16 16"
            width="16"
            height="16"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <rect x="5" y="5" width="8.5" height="8.5" />
            <path d="M3 10.5H2.5V2.5h8V3" />
          </svg>
        </button>
      </div>
    </div>
  {/if}

  {#snippet actions()}
    {#if !link}
      <button type="button" class="btn btn-secondary" onclick={onClose}>Close</button>
      <button type="submit" class="btn btn-primary" disabled={busy}>
        {busy ? "Creating…" : "Create link"}
      </button>
    {:else}
      {#if canShare}
        <button type="button" class="btn btn-secondary" onclick={shareViaSystem}>Share…</button>
      {/if}
      <button type="button" class="btn btn-secondary" onclick={onClose}>Close</button>
    {/if}
  {/snippet}
</Modal>

<style>
  .note {
    font-size: var(--label-md);
    color: var(--on-surface-variant);
    margin-bottom: var(--space-4);
  }

  /* One option per row: label on the left, its control on the right, every
     control's right edge on one line. Hints span the row below. */
  .options {
    display: grid;
    grid-template-columns: 1fr minmax(0, 14rem);
    align-items: center;
    gap: var(--space-3) var(--space-4);
  }

  .options > label {
    font-size: var(--body-md);
    color: var(--on-surface);
  }

  .options > input[type="text"],
  .options > select {
    width: 100%;
  }

  .options > .check {
    justify-self: end;
    width: 18px;
    height: 18px;
    margin: 0;
    accent-color: var(--primary);
  }

  .hint {
    grid-column: 1 / -1;
    margin-top: calc(-1 * var(--space-2));
    color: var(--on-surface-variant);
    font-size: var(--label-md);
  }

  .warning {
    color: var(--warning, #f8a010);
  }

  /* The QR code centered, the link (with its copy button) below it. */
  .share {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-4);
  }

  .link-field {
    position: relative;
    width: 100%;
  }

  .link {
    width: 100%;
    font-family: var(--font-mono);
    font-size: var(--label-md);
    padding-right: 2.5rem;
  }

  .copy-btn {
    position: absolute;
    top: 50%;
    right: 0.35rem;
    transform: translateY(-50%);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 2rem;
    height: 2rem;
    background: transparent;
    border: none;
    color: var(--on-surface-variant);
    cursor: pointer;
  }

  .copy-btn:hover {
    color: var(--primary);
  }

  .copy-btn:focus-visible {
    outline: 2px solid var(--primary);
    outline-offset: -2px;
  }

  /* Phones: label above its control, controls full width. */
  @media (max-width: 480px) {
    .options {
      grid-template-columns: 1fr auto;
    }

    .options > input[type="text"],
    .options > select {
      grid-column: 1 / -1;
      margin-top: calc(-1 * var(--space-2));
    }
  }
</style>
