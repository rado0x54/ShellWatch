<script lang="ts">
  import { onMount } from "svelte";
  import { account } from "$lib/stores/account.js";
  import { fetchSshKeys, sshKeys } from "$lib/stores/keys.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import {
    confirmPasskey,
    createPasskeyInvite,
    credentials,
    fetchActiveInvite,
    fetchCredentials,
    performStepUp,
    renamePasskey,
    startPasskeyRegistration,
    type PasskeyInvite,
  } from "$lib/stores/webauthn.js";
  import Modal from "$lib/components/Modal.svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";

  let revoking = $state(false);
  let registering = $state(false);
  let inviting = $state(false);
  let showAddModal = $state(false);
  // Single source of truth for the active invite slot for this account. Used
  // both for the on-page indicator (with live countdown) and as the prefilled
  // value when the user opens the Add-Passkey modal.
  let activeInvite = $state<PasskeyInvite | null>(null);
  let modalCreatedInvite = $state<PasskeyInvite | null>(null);
  let confirmingId = $state<string | null>(null);
  let editingId = $state<string | null>(null);
  let editLabel = $state("");
  // Ticks every second while an invite is active; drives the m:ss countdown
  // on both the on-page pill and the modal copy. Re-derived on each tick.
  let now = $state(Date.now());

  onMount(async () => {
    fetchCredentials();
    fetchSshKeys();
    try {
      activeInvite = await fetchActiveInvite();
    } catch (err) {
      toastError(errorMessage(err));
    }
  });

  // Run a 1Hz interval only while there's an active invite to count down.
  $effect(() => {
    if (!activeInvite) return;
    const id = setInterval(() => {
      now = Date.now();
    }, 1000);
    return () => clearInterval(id);
  });

  const inviteRemainingMs = $derived(activeInvite ? Date.parse(activeInvite.expiresAt) - now : 0);
  const inviteRemainingDisplay = $derived(formatRemaining(inviteRemainingMs));

  // Drop the invite from local state the instant it expires so the indicator
  // disappears without needing a server roundtrip. Server-side the slot has
  // already been swept by the same expiry deadline.
  //
  // If the user was on the link-display view of the modal at the moment of
  // expiry, close the whole modal — flipping it back to the picker would
  // yank the link out from under a possible mid-copy. They can re-issue.
  $effect(() => {
    if (activeInvite && inviteRemainingMs <= 0) {
      activeInvite = null;
      if (modalCreatedInvite) closeAddModal();
    }
  });

  function inviteUrl(token: string): string {
    return `${window.location.origin}/passkey-invite/${encodeURIComponent(token)}`;
  }

  /**
   * Open the modal on the picker view so "This device" stays reachable even
   * when an invite is already active. Use `openInviteModal` to jump straight
   * to the link-display view (the indicator pill takes that path).
   */
  function openAddModal() {
    modalCreatedInvite = null;
    showAddModal = true;
  }

  function openInviteModal() {
    modalCreatedInvite = activeInvite;
    showAddModal = true;
  }

  /**
   * "Another device" action. If a slot is still held we show the existing
   * link rather than supersede it — the user expressed intent to send a
   * link, not to invalidate the one they handed out 30 seconds ago.
   */
  async function handleInvite() {
    if (activeInvite) {
      modalCreatedInvite = activeInvite;
      return;
    }
    inviting = true;
    try {
      const inv = await createPasskeyInvite();
      activeInvite = inv;
      modalCreatedInvite = inv;
      now = Date.now();
    } catch (err) {
      toastError(`Could not create invite: ${errorMessage(err)}`);
    }
    inviting = false;
  }

  function closeAddModal() {
    showAddModal = false;
    modalCreatedInvite = null;
  }

  function formatRemaining(ms: number): string {
    if (ms <= 0) return "0:00";
    const totalSec = Math.ceil(ms / 1000);
    const mins = Math.floor(totalSec / 60);
    const secs = totalSec % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  }

  // The confirm flow runs through a modal so the fingerprint sits in a real
  // <code> block — not a confirm() text blob — and the user has to tick an
  // explicit "verified" checkbox before the activation button enables. The
  // fingerprint is the only thing that catches an intercepted-link attack, so
  // this is the moment to slow the user down.
  let confirmTarget = $state<{
    id: string;
    label: string;
    fingerprint: string | null;
  } | null>(null);
  let confirmVerified = $state(false);

  function openConfirmModal(id: string) {
    const cred = $credentials.find((c) => c.id === id);
    if (!cred) return;
    confirmTarget = { id, label: cred.label, fingerprint: cred.fingerprint };
    confirmVerified = false;
  }

  function closeConfirmModal() {
    confirmTarget = null;
    confirmVerified = false;
  }

  async function handleConfirm() {
    if (!confirmTarget) return;
    confirmingId = confirmTarget.id;
    try {
      await confirmPasskey(confirmTarget.id);
      closeConfirmModal();
    } catch (err) {
      toastError(`Could not confirm: ${errorMessage(err)}`);
    }
    confirmingId = null;
  }

  function sanitizeSegment(s: string): string {
    return s
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "_")
      .replace(/_+/g, "_")
      .replace(/^_|_$/g, "");
  }

  function sshComment(label: string): string {
    const host = sanitizeSegment(window.location.hostname);
    const name = sanitizeSegment($account?.name ?? "unknown");
    const key = sanitizeSegment(label);
    return `${host}-${name}-${key}`;
  }

  function copyKey(key: string, btn: HTMLButtonElement) {
    navigator.clipboard.writeText(key);
    const original = btn.innerHTML;
    btn.innerHTML = "&#10003;";
    setTimeout(() => {
      btn.innerHTML = original;
    }, 1500);
  }

  async function handleRevoke(id: string) {
    // TODO: use basePath store instead of window.__BASE_PATH__ (applies to this fn and handleRevokeFileKey)
    const target = $credentials.find((c) => c.id === id);
    // Pending credentials don't count toward "last active" — they can't log in.
    if (target?.state !== "pending_confirmation") {
      const activeCount = $credentials.filter((c) => !c.revoked && c.state === "active").length;
      if (activeCount <= 1) {
        // Client-side guard for UX; also enforced server-side in the revoke endpoint
        toastError("Cannot revoke the last active passkey.");
        return;
      }
    }
    if (!confirm("Revoke this passkey? This is permanent and cannot be undone.")) return;
    revoking = true;
    try {
      // Step-up before revoke. The user has to assert with an existing
      // passkey, then the resulting single-use token is forwarded as the
      // X-Shellwatch-Stepup-Token header. Cancelling the prompt aborts here without
      // hitting the revoke endpoint.
      let stepUpToken: string;
      try {
        stepUpToken = await performStepUp("revoke_passkey");
      } catch (err) {
        toastError(`Step-up required: ${errorMessage(err)}`);
        revoking = false;
        return;
      }

      const base = (window as unknown as { __BASE_PATH__?: string }).__BASE_PATH__ ?? "";
      const res = await fetch(`${base}/api/webauthn/credentials/${id}/revoke`, {
        method: "POST",
        headers: { "X-Shellwatch-Stepup-Token": stepUpToken },
      });
      if (!res.ok) {
        const err = await res.json();
        toastError(err.error || "Failed to revoke");
      }
      await fetchCredentials();
    } catch (err) {
      toastError(errorMessage(err));
    }
    revoking = false;
  }

  async function handleRevokeFileKey(id: string) {
    if (!confirm("Revoke this SSH key? This is permanent and cannot be undone.")) return;
    revoking = true;
    try {
      const base = (window as unknown as { __BASE_PATH__?: string }).__BASE_PATH__ ?? "";
      const res = await fetch(`${base}/api/keys/${id}`, { method: "DELETE" });
      if (!res.ok) {
        const err = await res.json();
        toastError(err.error || "Failed to revoke");
      }
      await fetchSshKeys();
    } catch (err) {
      toastError(errorMessage(err));
    }
    revoking = false;
  }

  async function handleRegister() {
    registering = true;
    try {
      // Closing first means the WebAuthn prompt isn't fighting the modal for
      // focus on browsers that auto-focus the dialog.
      showAddModal = false;
      const result = await startPasskeyRegistration($account?.name);
      await fetchCredentials();
      // Start inline rename on the newly registered passkey
      editingId = result.credentialId;
      editLabel = result.label;
    } catch (err) {
      toastError(`Registration failed: ${errorMessage(err)}`);
    }
    registering = false;
  }

  function startRename(id: string, currentLabel: string) {
    editingId = id;
    editLabel = currentLabel;
  }

  async function saveRename() {
    if (!editingId || !editLabel.trim()) return;
    try {
      await renamePasskey(editingId, editLabel.trim());
    } catch (err) {
      toastError(errorMessage(err));
    }
    editingId = null;
  }

  function cancelRename() {
    editingId = null;
  }

  function handleRenameKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") saveRename();
    if (e.key === "Escape") cancelRename();
  }

  function shortFingerprint(fp: string | null): string {
    if (!fp) return "—";
    return fp.length > 20 ? `${fp.slice(0, 20)}...` : fp;
  }

  function formatDate(iso: string | null): string {
    if (!iso) return "Never";
    return iso.slice(0, 10);
  }

  const hasAuthorizedKeys = $derived($credentials.some((pk) => pk.authorizedKeysEntry));
  const fileKeys = $derived($sshKeys.filter((k) => k.type === "file"));
</script>

<section>
  <!-- Passkeys -->
  <h2>Passkeys</h2>
  <SettingsList empty={$credentials.length === 0} emptyText="No passkeys registered">
    {#each $credentials as pk (pk.id)}
      <SettingsRow>
        {#snippet primary()}
          {#if editingId === pk.id}
            <!-- svelte-ignore a11y_autofocus -->
            <input
              type="text"
              class="inline-rename"
              bind:value={editLabel}
              onkeydown={handleRenameKeydown}
              onblur={cancelRename}
              autofocus
            />
          {:else}
            <button
              class="row-label label-btn"
              class:revoked={pk.revoked}
              title="Rename"
              disabled={pk.revoked}
              onclick={() => startRename(pk.id, pk.label)}>{pk.label}</button
            >
          {/if}
          {#if pk.revoked}
            <span class="badge badge-unavailable">revoked</span>
          {:else if pk.state === "pending_confirmation"}
            <span class="badge badge-pending">pending confirmation</span>
          {:else}
            <span class="badge badge-available">active</span>
          {/if}
          <span class="meta-mono">{pk.algorithm}</span>
        {/snippet}
        {#snippet secondary()}
          <span title={pk.fingerprint ?? ""}>{shortFingerprint(pk.fingerprint)}</span>
          <span class="row-dot">·</span>created {formatDate(pk.createdAt)}
          <span class="row-dot">·</span>last used {formatDate(pk.lastUsedAt)}
        {/snippet}
        {#snippet actions()}
          {#if pk.authorizedKeysEntry && !pk.revoked && pk.state === "active"}
            <button
              class="btn btn-secondary"
              title="Copy SSH public key"
              onclick={(e) =>
                copyKey(
                  `${pk.authorizedKeysEntry} ${sshComment(pk.label)}`,
                  e.currentTarget as HTMLButtonElement,
                )}>Copy SSH PubKey</button
            >
          {/if}
          {#if !pk.revoked && pk.state === "pending_confirmation"}
            <button
              class="btn btn-primary"
              disabled={confirmingId === pk.id}
              onclick={() => openConfirmModal(pk.id)}
              >{confirmingId === pk.id ? "Confirming..." : "Confirm"}</button
            >
          {/if}
          {#if !pk.revoked}
            <button
              class="btn btn-secondary"
              disabled={revoking}
              onclick={() => handleRevoke(pk.id)}>Revoke</button
            >
          {/if}
        {/snippet}
      </SettingsRow>
    {/each}
  </SettingsList>

  <div class="register-section">
    <button class="btn btn-primary" onclick={openAddModal}>Add passkey</button>
    {#if activeInvite}
      <button class="invite-pill" type="button" onclick={openInviteModal} title="Show invite link">
        <span class="invite-pill-dot" aria-hidden="true"></span>
        <span class="invite-pill-text">Invite link active</span>
        <span class="invite-pill-timer">{inviteRemainingDisplay}</span>
      </button>
    {/if}
  </div>

  {#if showAddModal}
    <Modal title={modalCreatedInvite ? "Invite link" : "Add a passkey"} onClose={closeAddModal}>
      {#if modalCreatedInvite}
        <div class="invite-status">
          <span class="invite-status-dot" aria-hidden="true"></span>
          <span class="invite-status-label">Active</span>
          <span class="invite-status-timer">{inviteRemainingDisplay}</span>
        </div>
        <p class="modal-desc">
          Open on the other device. Single-use; come back here to <strong>Confirm</strong>.
        </p>
        <div class="invite-link">
          <code>{inviteUrl(modalCreatedInvite.token)}</code>
          <button
            class="invite-link-copy"
            type="button"
            aria-label="Copy invite link"
            onclick={(e) =>
              copyKey(inviteUrl(modalCreatedInvite!.token), e.currentTarget as HTMLButtonElement)}
            >Copy</button
          >
        </div>
      {:else}
        <p class="modal-desc">From what device should the passkey be added?</p>

        <button class="add-option" type="button" disabled={registering} onclick={handleRegister}>
          <span class="add-option-title">This device</span>
          <span class="add-option-body"> Use this browser or a security key plugged in here. </span>
          <span class="add-option-cta" aria-hidden="true">{registering ? "…" : "→"}</span>
        </button>

        <button class="add-option" type="button" disabled={inviting} onclick={handleInvite}>
          <span class="add-option-title">
            Other device
            {#if activeInvite}
              <span class="add-option-tag">Active · {inviteRemainingDisplay}</span>
            {/if}
          </span>
          <span class="add-option-body">
            Generate a one-time link to share with the other device.
          </span>
          <span class="add-option-cta" aria-hidden="true">{inviting ? "…" : "→"}</span>
        </button>
      {/if}

      {#snippet actions()}
        <button class="btn btn-secondary" type="button" onclick={closeAddModal}
          >{modalCreatedInvite ? "Done" : "Cancel"}</button
        >
      {/snippet}
    </Modal>
  {/if}

  {#if confirmTarget}
    {@const target = confirmTarget}
    <Modal title="Activate this passkey?" onClose={closeConfirmModal}>
      <p class="modal-desc">
        Activating <strong>{target.label}</strong> lets it log in and sign SSH for this account. Confirm
        only after verifying the fingerprint below matches the one shown on the device that registered
        the passkey.
      </p>

      {#if target.fingerprint}
        <div class="confirm-fingerprint">
          <span class="confirm-fingerprint-label">Fingerprint</span>
          <code class="confirm-fingerprint-value">{target.fingerprint}</code>
        </div>
      {:else}
        <p class="modal-hint">
          No fingerprint is available for this credential. Verify out-of-band (e.g. by asking the
          person who registered it) that they expected to enroll on this account.
        </p>
      {/if}

      <label class="confirm-check">
        <input type="checkbox" bind:checked={confirmVerified} />
        <span>I've verified this fingerprint matches the one shown on the registering device.</span>
      </label>

      {#snippet actions()}
        <button class="btn btn-secondary" type="button" onclick={closeConfirmModal}>Cancel</button>
        <button
          class="btn btn-primary"
          type="button"
          disabled={!confirmVerified || confirmingId === target.id}
          onclick={handleConfirm}
        >
          {confirmingId === target.id ? "Activating…" : "Activate passkey"}
        </button>
      {/snippet}
    </Modal>
  {/if}

  {#if hasAuthorizedKeys}
    <div class="settings-info">
      <h3>SSH Server Setup</h3>
      <p>Add this line to <code>/etc/ssh/sshd_config</code> on your remote server:</p>
      <pre
        class="code-block">PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com</pre>
      <p>Then add the passkey's SSH public key to <code>~/.ssh/authorized_keys</code>.</p>
    </div>
  {/if}

  <!-- File-based SSH Keys (admin only) -->
  {#if $account?.isAdmin && fileKeys.length > 0}
    <h2 class="section-divider">File-Based SSH Keys</h2>
    <SettingsList>
      {#each fileKeys as k (k.id)}
        <SettingsRow>
          {#snippet primary()}
            <span class="row-label" class:revoked={k.revoked}>{k.label}</span>
            {#if k.revoked}
              <span class="badge badge-unavailable">revoked</span>
            {:else if !k.available}
              <span class="badge badge-unavailable">unavailable</span>
            {:else}
              <span class="badge badge-available">available</span>
            {/if}
            <span class="meta-mono">{k.algorithm}</span>
          {/snippet}
          {#snippet secondary()}
            <span title={k.fingerprint ?? ""}>{shortFingerprint(k.fingerprint)}</span>
            <span class="row-dot">·</span>created {formatDate(k.createdAt)}
            <span class="row-dot">·</span>last used {formatDate(k.lastUsedAt)}
          {/snippet}
          {#snippet actions()}
            {#if k.authorizedKeysEntry && !k.revoked}
              <button
                class="btn btn-secondary"
                title="Copy SSH public key"
                onclick={(e) =>
                  copyKey(k.authorizedKeysEntry!, e.currentTarget as HTMLButtonElement)}
                >Copy SSH PubKey</button
              >
            {/if}
            {#if !k.revoked}
              <button
                class="btn btn-secondary"
                disabled={revoking}
                onclick={() => handleRevokeFileKey(k.id)}>Revoke</button
              >
            {/if}
          {/snippet}
        </SettingsRow>
      {/each}
    </SettingsList>
  {/if}
</section>

<style>
  h2 {
    font-size: 0.75rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .section-divider {
    margin-top: 2rem;
  }

  .row-label {
    font-weight: 600;
    font-size: var(--body-md);
    color: var(--on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 100%;
  }

  .row-label.revoked {
    opacity: 0.5;
  }

  .meta-mono {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    color: var(--on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .row-dot {
    color: var(--on-surface-faint);
    margin: 0 var(--space-2);
  }

  .register-section {
    margin-top: var(--space-5);
    display: flex;
    align-items: center;
    gap: var(--space-3);
    flex-wrap: wrap;
  }

  /* Live indicator that an invite slot is currently held. Pill is clickable
     and re-opens the Add-Passkey modal in the link-display state. */
  .invite-pill {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: 0.35rem 0.75rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 999px;
    color: var(--on-surface);
    font: inherit;
    font-size: 0.78rem;
    cursor: pointer;
    transition: border-color 0.15s;
  }

  .invite-pill:hover {
    border-color: var(--primary);
  }

  .invite-pill-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--primary);
    box-shadow: 0 0 0 0 currentColor;
    animation: invite-pulse 1.6s ease-out infinite;
  }

  .invite-pill-text {
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-size: 0.65rem;
    font-weight: 600;
  }

  .invite-pill-timer {
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
    color: var(--on-surface);
  }

  @keyframes invite-pulse {
    0% {
      box-shadow: 0 0 0 0 var(--primary);
      opacity: 1;
    }
    70% {
      box-shadow: 0 0 0 6px transparent;
      opacity: 0.6;
    }
    100% {
      box-shadow: 0 0 0 0 transparent;
      opacity: 1;
    }
  }

  .modal-desc {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0 0 var(--space-3);
    line-height: 1.5;
  }

  .add-option {
    position: relative;
    display: block;
    width: 100%;
    text-align: left;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: var(--space-3);
    /* Reserve space on the right for the circular CTA so long body text
       doesn't run into it on narrow viewports. */
    padding-right: 4rem;
    margin-bottom: var(--space-2);
    cursor: pointer;
    color: inherit;
    font: inherit;
    transition:
      border-color 0.15s,
      background-color 0.15s,
      transform 0.1s;
  }

  .add-option:hover:not(:disabled) {
    border-color: var(--green, #4ade80);
    background: var(--surface-container-low, var(--bg-primary));
  }

  .add-option:hover:not(:disabled) .add-option-cta {
    transform: translateX(2px);
  }

  .add-option:active:not(:disabled) {
    transform: scale(0.99);
  }

  .add-option:disabled {
    opacity: 0.6;
    cursor: default;
  }

  .add-option-title {
    display: block;
    font-weight: 600;
    font-size: var(--body-md);
    margin-bottom: var(--space-1);
  }

  .add-option-body {
    display: block;
    font-size: 0.8rem;
    color: var(--text-muted);
    line-height: 1.5;
  }

  .add-option-tag {
    display: inline-block;
    margin-left: var(--space-2);
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--primary);
    border: 1px solid var(--primary);
    border-radius: 999px;
    padding: 0.05rem 0.5rem;
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
    vertical-align: middle;
  }

  /* Green chevron disc anchored to the bottom-right of each card — the
     visible affordance that the whole card is tappable. The card's own
     button element handles the click; the disc is purely decorative. */
  .add-option-cta {
    position: absolute;
    right: var(--space-3);
    bottom: var(--space-3);
    width: 2.25rem;
    height: 2.25rem;
    border-radius: 50%;
    background: var(--green, #4ade80);
    color: #08110b;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 1.05rem;
    font-weight: 700;
    line-height: 1;
    pointer-events: none;
    box-shadow: 0 2px 8px color-mix(in srgb, var(--green, #4ade80) 45%, transparent);
    transition:
      transform 0.15s,
      box-shadow 0.15s;
  }

  .add-option:disabled .add-option-cta {
    background: var(--border);
    color: var(--text-muted);
    box-shadow: none;
  }

  /* Status row: green dot + "Active" label + monospace timer. Sits at the
     top of the link-display modal view as the green accent. */
  .invite-status {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: 0.3rem 0.7rem;
    margin-bottom: var(--space-3);
    background: color-mix(in srgb, var(--green, #4ade80) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--green, #4ade80) 50%, transparent);
    border-radius: 999px;
  }

  .invite-status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--green, #4ade80);
    box-shadow: 0 0 6px color-mix(in srgb, var(--green, #4ade80) 70%, transparent);
    animation: invite-pulse 1.6s ease-out infinite;
  }

  .invite-status-label {
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--green, #4ade80);
  }

  .invite-status-timer {
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
    font-size: 0.85rem;
    color: var(--green, #4ade80);
    font-weight: 600;
  }

  /* Link box with the Copy button laid over the right edge — no separate
     button cell, the box is the unit. */
  .invite-link {
    position: relative;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 4.5rem 0.6rem 0.75rem;
    margin: 0 0 var(--space-2);
    text-align: left;
  }

  .invite-link code {
    font-family: var(--font-mono);
    font-size: 0.78rem;
    overflow-wrap: anywhere;
    word-break: break-all;
    color: var(--on-surface);
  }

  .invite-link-copy {
    position: absolute;
    top: 50%;
    right: 0.4rem;
    transform: translateY(-50%);
    padding: 0.3rem 0.65rem;
    background: var(--bg-secondary);
    color: var(--on-surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 600;
    cursor: pointer;
    transition:
      border-color 0.15s,
      color 0.15s;
  }

  .invite-link-copy:hover {
    border-color: var(--green, #4ade80);
    color: var(--green, #4ade80);
  }

  .modal-hint {
    font-size: 0.78rem;
    color: var(--text-muted);
    margin: 0;
    line-height: 1.5;
  }

  /* Confirm-passkey modal: prominent fingerprint block + verified checkbox. */
  .confirm-fingerprint {
    margin: var(--space-3) 0;
    padding: 0.75rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg-primary);
    text-align: left;
  }

  .confirm-fingerprint-label {
    display: block;
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 0.4rem;
  }

  .confirm-fingerprint-value {
    display: block;
    font-family: var(--font-mono);
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--on-surface);
    word-break: break-all;
  }

  .confirm-check {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    margin: var(--space-3) 0 0;
    font-size: 0.82rem;
    color: var(--on-surface);
    cursor: pointer;
    line-height: 1.45;
  }

  .confirm-check input[type="checkbox"] {
    margin-top: 0.2rem;
    flex-shrink: 0;
  }

  .label-btn {
    background: none;
    border: none;
    color: var(--on-surface);
    cursor: pointer;
    padding: 0;
    font: inherit;
    text-align: left;
  }

  .label-btn:hover:not(:disabled) {
    color: var(--primary);
    text-decoration: underline;
  }

  .label-btn:disabled {
    cursor: default;
  }

  .inline-rename {
    width: 100%;
    padding: var(--space-1) 0;
    border: none;
    border-bottom: 1px solid var(--primary);
    background: transparent;
    color: var(--on-surface);
    font: inherit;
    font-size: var(--body-md);
  }

  .inline-rename:focus {
    outline: none;
    box-shadow: 0 2px 0 -1px var(--primary);
  }
</style>
