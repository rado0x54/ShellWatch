<script lang="ts">
  import { onMount } from "svelte";
  import Modal from "$lib/components/Modal.svelte";
  import { apiKeys, fetchApiKeys, generateApiKey, revokeApiKey } from "$lib/stores/keys.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";

  let label = $state("");
  let scopeMcp = $state(true);
  let scopeAgent = $state(false);
  let showKeyModal = $state(false);
  let generatedKey = $state("");

  onMount(() => {
    fetchApiKeys();
  });

  async function handleGenerate() {
    if (!label.trim()) return;
    const scopes: string[] = [];
    if (scopeMcp) scopes.push("mcp");
    if (scopeAgent) scopes.push("agent");
    if (scopes.length === 0) {
      toastError("Select at least one scope");
      return;
    }
    try {
      generatedKey = await generateApiKey(label.trim(), scopes);
      showKeyModal = true;
      label = "";
      scopeMcp = true;
      scopeAgent = false;
    } catch (err) {
      toastError(errorMessage(err));
    }
  }

  async function handleRevoke(id: string) {
    if (confirm("Revoke this API key?")) {
      try {
        await revokeApiKey(id);
      } catch (err) {
        toastError(errorMessage(err));
      }
    }
  }

  function handleCopy(btn: HTMLButtonElement) {
    navigator.clipboard.writeText(generatedKey);
    btn.textContent = "Copied!";
  }

  function handleCloseModal() {
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
            <button class="btn btn-secondary" onclick={() => handleRevoke(k.id)}>Revoke</button>
          {/if}
        {/snippet}
      </SettingsRow>
    {/each}
  </SettingsList>

  <div class="settings-form">
    <h3>Generate API Key</h3>
    <div class="form-row">
      <input
        type="text"
        placeholder="Label (e.g., Claude Agent)"
        bind:value={label}
        style="flex: 1"
      />
      <button class="btn btn-primary" onclick={handleGenerate}>Generate</button>
    </div>
    <h4 class="scope-heading">Scopes</h4>
    <div class="scope-row">
      <label class="scope-option">
        <input type="checkbox" bind:checked={scopeMcp} />
        <span>mcp</span>
        <span class="scope-hint">— MCP server access</span>
      </label>
      <label class="scope-option">
        <input type="checkbox" bind:checked={scopeAgent} />
        <span>agent</span>
        <span class="scope-hint">— SSH agent socket forwarding</span>
      </label>
    </div>
  </div>

  {#if showKeyModal}
    <Modal title="API Key Created" onClose={handleCloseModal}>
      <p class="modal-desc">Copy this key now — it will not be shown again.</p>
      <pre class="code-block key-value">{generatedKey}</pre>
      {#snippet actions()}
        <button
          class="btn btn-primary"
          onclick={(e) => handleCopy(e.currentTarget as HTMLButtonElement)}>Copy</button
        >
        <button class="btn btn-secondary" onclick={handleCloseModal}>Done</button>
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

  .modal-desc {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0.75rem 0;
  }

  .key-value {
    user-select: all;
    cursor: text;
  }

  .scope-heading {
    margin: 0.75rem 0 0.25rem;
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--text-muted);
  }

  .scope-row {
    display: flex;
    gap: 1.5rem;
    margin-top: 0.5rem;
    font-size: 0.85rem;
  }

  .scope-option {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    cursor: pointer;
  }

  .scope-hint {
    color: var(--text-muted);
    font-size: 0.75rem;
  }
</style>
