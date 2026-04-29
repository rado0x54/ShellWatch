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
    fetchCredentials,
    fetchPasskeyInvites,
    passkeyInvites,
    renamePasskey,
    revokePasskeyInvite,
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
  // Set after a successful Invite creation; switches the modal from the
  // pick-flow view to the link-display view. The list endpoint always returns
  // the token while the invite is `pending`, so the link is recoverable from
  // the Pending Invites section even after the modal closes.
  let modalCreatedInvite = $state<PasskeyInvite | null>(null);
  let confirmingId = $state<string | null>(null);
  let editingId = $state<string | null>(null);
  let editLabel = $state("");

  onMount(() => {
    fetchCredentials();
    fetchSshKeys();
    fetchPasskeyInvites().catch((err) => toastError(errorMessage(err)));
  });

  function inviteUrl(token: string): string {
    return `${window.location.origin}/passkey-invite/${encodeURIComponent(token)}`;
  }

  async function handleInvite() {
    inviting = true;
    try {
      const invite = await createPasskeyInvite();
      // Stay in the modal: switch to the link-display view so the user can
      // copy the URL right where they triggered the action.
      modalCreatedInvite = invite;
    } catch (err) {
      toastError(`Could not create invite: ${errorMessage(err)}`);
    }
    inviting = false;
  }

  function closeAddModal() {
    showAddModal = false;
    modalCreatedInvite = null;
  }

  async function handleRevokeInvite(id: string) {
    if (
      !confirm(
        "Revoke this invite? Any registered-but-unconfirmed passkey from it will also be revoked.",
      )
    )
      return;
    try {
      await revokePasskeyInvite(id);
      if (modalCreatedInvite?.id === id) closeAddModal();
    } catch (err) {
      toastError(errorMessage(err));
    }
  }

  async function handleConfirm(id: string) {
    confirmingId = id;
    try {
      await confirmPasskey(id);
      await fetchPasskeyInvites();
    } catch (err) {
      toastError(`Could not confirm: ${errorMessage(err)}`);
    }
    confirmingId = null;
  }

  function formatExpiry(iso: string): string {
    const ms = Date.parse(iso) - Date.now();
    if (ms <= 0) return "expired";
    const mins = Math.round(ms / 60_000);
    if (mins < 60) return `${mins}m`;
    const hours = Math.round(mins / 60);
    return `${hours}h`;
  }

  const pendingInvites = $derived(
    $passkeyInvites.filter((i) => i.status === "pending" || i.status === "registered"),
  );

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
      const base = (window as unknown as { __BASE_PATH__?: string }).__BASE_PATH__ ?? "";
      const res = await fetch(`${base}/api/webauthn/credentials/${id}/revoke`, { method: "POST" });
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
              onclick={() => handleConfirm(pk.id)}
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
    <button class="btn btn-primary" onclick={() => (showAddModal = true)}>Add passkey</button>
  </div>

  {#if showAddModal}
    <Modal title={modalCreatedInvite ? "Invite created" : "Add a passkey"} onClose={closeAddModal}>
      {#if modalCreatedInvite?.token}
        <p class="modal-desc">
          Single-use · expires in {formatExpiry(modalCreatedInvite.expiresAt)}. Open this link on
          the device you want to enroll. It can only complete registration once. After the device
          registers, come back here and click <strong>Confirm</strong> on the new passkey.
        </p>
        <div class="invite-link-row">
          <code class="invite-link">{inviteUrl(modalCreatedInvite.token)}</code>
          <button
            class="btn btn-secondary"
            type="button"
            onclick={(e) =>
              copyKey(inviteUrl(modalCreatedInvite!.token!), e.currentTarget as HTMLButtonElement)}
            >Copy</button
          >
        </div>
        <p class="modal-hint">
          You can re-copy this link anytime from <strong>Pending invites</strong> below until it expires,
          is consumed, or is revoked.
        </p>
      {:else}
        <p class="modal-desc">
          Pick where the new passkey lives. Both options enroll a passkey on this account.
        </p>

        <button class="add-option" type="button" disabled={registering} onclick={handleRegister}>
          <span class="add-option-title">This device</span>
          <span class="add-option-body">
            Use the authenticator built into this browser or a security key plugged in here.
            Registration runs immediately and the passkey is active right away — you can use it for
            login and SSH on this account.
          </span>
          <span class="add-option-cta"
            >{registering ? "Waiting for passkey…" : "Register here →"}</span
          >
        </button>

        <button class="add-option" type="button" disabled={inviting} onclick={handleInvite}>
          <span class="add-option-title">Another device</span>
          <span class="add-option-body">
            Generate a single-use link (valid for 1 hour) to open on the other device. That device
            completes the WebAuthn ceremony, then the new passkey sits in
            <em>pending confirmation</em>
            — it cannot log in, sign anything, or be copied as an SSH key until you come back here and
            click <strong>Confirm</strong>.
          </span>
          <span class="add-option-cta"
            >{inviting ? "Creating invite…" : "Create invite link →"}</span
          >
        </button>
      {/if}

      {#snippet actions()}
        <button class="btn btn-secondary" type="button" onclick={closeAddModal}
          >{modalCreatedInvite ? "Done" : "Cancel"}</button
        >
      {/snippet}
    </Modal>
  {/if}

  {#if pendingInvites.length > 0}
    <h3 class="subhead">Pending invites</h3>
    <SettingsList>
      {#each pendingInvites as inv (inv.id)}
        <SettingsRow>
          {#snippet primary()}
            <span class="row-label">{inv.label}</span>
            {#if inv.status === "registered"}
              <span class="badge badge-pending">awaiting confirmation</span>
            {:else}
              <span class="badge badge-pending">link issued</span>
            {/if}
          {/snippet}
          {#snippet secondary()}
            {#if inv.status === "pending"}
              <span>expires in {formatExpiry(inv.expiresAt)}</span>
            {:else if inv.status === "registered"}
              <span>passkey registered, confirm above</span>
            {/if}
          {/snippet}
          {#snippet actions()}
            {#if inv.token}
              <button
                class="btn btn-secondary"
                title="Copy invite link"
                onclick={(e) =>
                  copyKey(inviteUrl(inv.token!), e.currentTarget as HTMLButtonElement)}
                >Copy link</button
              >
            {/if}
            <button class="btn btn-secondary" onclick={() => handleRevokeInvite(inv.id)}
              >Revoke</button
            >
          {/snippet}
        </SettingsRow>
      {/each}
    </SettingsList>
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
  }

  .modal-desc {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0 0 var(--space-3);
    line-height: 1.5;
  }

  .add-option {
    display: block;
    width: 100%;
    text-align: left;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: var(--space-3);
    margin-bottom: var(--space-2);
    cursor: pointer;
    color: inherit;
    font: inherit;
    transition:
      border-color 0.15s,
      background-color 0.15s;
  }

  .add-option:hover:not(:disabled) {
    border-color: var(--primary);
    background: var(--surface-container-low, var(--bg-primary));
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

  .add-option-cta {
    display: block;
    margin-top: var(--space-2);
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--primary);
  }

  .subhead {
    font-size: 0.7rem;
    font-weight: 600;
    margin: var(--space-5) 0 var(--space-2);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .invite-link-row {
    display: flex;
    gap: var(--space-2);
    align-items: center;
    margin-bottom: var(--space-2);
  }

  .invite-link {
    flex: 1;
    min-width: 0;
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    overflow-wrap: anywhere;
    word-break: break-all;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: var(--space-1) var(--space-2);
  }

  .modal-hint {
    font-size: 0.78rem;
    color: var(--text-muted);
    margin: 0;
    line-height: 1.5;
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
