<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import Modal from "$lib/components/Modal.svelte";
  import ConfirmDialog from "$lib/components/ConfirmDialog.svelte";
  import { apiKeys, fetchApiKeys, generateApiKey, revokeApiKey } from "$lib/stores/keys.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";

  let label = $state("");
  let scopeMcp = $state(true);
  let scopeAgent = $state(false);
  let generating = $state(false);
  // Two-stage flow: open the form modal, fill in label + scopes + Generate,
  // then the key-display modal opens with the freshly-minted key (shown once).
  let formModalOpen = $state(false);
  let showKeyModal = $state(false);
  let generatedKey = $state("");
  let revokeTarget = $state<{ id: string; label: string } | null>(null);
  let revoking = $state(false);

  onMount(() => {
    fetchApiKeys();
  });

  function openGenerateModal() {
    label = "";
    scopeMcp = true;
    scopeAgent = false;
    formModalOpen = true;
  }

  function closeGenerateModal() {
    if (generating) return;
    formModalOpen = false;
  }

  async function handleGenerate() {
    if (generating) return;
    if (!label.trim()) {
      toastError("Label is required");
      return;
    }
    const scopes: string[] = [];
    if (scopeMcp) scopes.push("mcp");
    if (scopeAgent) scopes.push("agent");
    if (scopes.length === 0) {
      toastError("Select at least one scope");
      return;
    }
    generating = true;
    try {
      generatedKey = await generateApiKey(label.trim(), scopes);
      formModalOpen = false;
      showKeyModal = true;
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      generating = false;
    }
  }

  function openRevoke(id: string, keyLabel: string) {
    revokeTarget = { id, label: keyLabel };
  }

  function closeRevoke() {
    if (revoking) return;
    revokeTarget = null;
  }

  async function handleRevoke() {
    if (!revokeTarget) return;
    revoking = true;
    try {
      await revokeApiKey(revokeTarget.id);
      revokeTarget = null;
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      revoking = false;
    }
  }

  function handleCopy(btn: HTMLButtonElement) {
    navigator.clipboard.writeText(generatedKey);
    btn.textContent = "Copied!";
  }

  function handleCloseKeyModal() {
    showKeyModal = false;
    generatedKey = "";
  }
</script>

<section>
  <h2>API Keys</h2>
  <SettingsList empty={$apiKeys.length === 0} emptyText="No API keys configured">
    {#each $apiKeys as k (k.id)}
      <SettingsRow>
        {#snippet primary()}
          <span class="row-label">{k.label}</span>
          {#if k.enabled}
            <span class="badge badge-available">active</span>
          {:else}
            <span class="badge badge-unavailable">revoked</span>
          {/if}
          <span class="meta-mono">{k.scopes.join(" ")}</span>
        {/snippet}
        {#snippet secondary()}
          {k.keyPrefix}…<span class="row-dot">·</span>created {k.createdAt.slice(0, 10)}
        {/snippet}
        {#snippet actions()}
          {#if k.enabled}
            <button
              type="button"
              class="btn btn-secondary"
              onclick={() => openRevoke(k.id, k.label)}>Revoke</button
            >
          {/if}
        {/snippet}
      </SettingsRow>
    {/each}
  </SettingsList>

  <div class="register-section">
    <button type="button" class="btn btn-primary" onclick={openGenerateModal}>
      Generate API Key
    </button>
  </div>

  {#if revokeTarget}
    <ConfirmDialog
      title="Revoke API key?"
      confirmLabel="Revoke"
      onConfirm={handleRevoke}
      onCancel={closeRevoke}
      processing={revoking}
    >
      <p class="modal-desc">
        Revoke <strong>{revokeTarget.label}</strong>? Any clients still using it will start failing
        on the next request.
      </p>
    </ConfirmDialog>
  {/if}

  {#if formModalOpen}
    <Modal
      title="Generate API Key"
      onClose={closeGenerateModal}
      onSubmit={handleGenerate}
      width="480px"
    >
      <div class="field">
        <label for="apikey-label">Label</label>
        <input
          id="apikey-label"
          type="text"
          placeholder="e.g. Claude Agent"
          bind:value={label}
          disabled={generating}
        />
      </div>

      <div class="field">
        <span class="field-label">Scopes</span>
        <label class="scope-option">
          <input type="checkbox" bind:checked={scopeMcp} disabled={generating} />
          <span>mcp</span>
          <span class="scope-hint">— MCP server access</span>
        </label>
        <label class="scope-option">
          <input type="checkbox" bind:checked={scopeAgent} disabled={generating} />
          <span>agent</span>
          <span class="scope-hint">— SSH agent socket forwarding</span>
        </label>
      </div>

      {#snippet actions()}
        <button
          type="button"
          class="btn btn-secondary"
          onclick={closeGenerateModal}
          disabled={generating}
        >
          Cancel
        </button>
        <button type="submit" class="btn btn-primary" disabled={generating}>
          {generating ? "Generating…" : "Generate"}
        </button>
      {/snippet}
    </Modal>
  {/if}

  {#if showKeyModal}
    <Modal title="API Key Created" onClose={handleCloseKeyModal}>
      <p class="modal-desc">Copy this key now — it will not be shown again.</p>
      <pre class="code-block key-value">{generatedKey}</pre>
      {#snippet actions()}
        <button
          type="button"
          class="btn btn-primary"
          onclick={(e) => handleCopy(e.currentTarget as HTMLButtonElement)}>Copy</button
        >
        <button type="button" class="btn btn-secondary" onclick={handleCloseKeyModal}>Done</button>
      {/snippet}
    </Modal>
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

  .row-label {
    font-weight: 600;
    font-size: var(--body-md);
    color: var(--on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 100%;
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

  .modal-desc {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0.75rem 0;
  }

  .key-value {
    user-select: all;
    cursor: text;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    margin-top: 0.85rem;
  }

  .field label,
  .field .field-label {
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .scope-option {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    cursor: pointer;
    font-size: 0.85rem;
    font-weight: 400;
    color: var(--on-surface);
    text-transform: none;
    letter-spacing: 0;
    margin-top: 0.35rem;
  }

  .scope-hint {
    color: var(--text-muted);
    font-size: 0.75rem;
  }
</style>
