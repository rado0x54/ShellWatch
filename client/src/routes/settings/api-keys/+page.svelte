<script lang="ts">
  import { onMount } from "svelte";
  import { apiKeys, fetchApiKeys, generateApiKey, revokeApiKey } from "$lib/stores/keys.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";

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
  <table class="settings-table">
    <thead>
      <tr>
        <th>Label</th>
        <th>Prefix</th>
        <th>Scopes</th>
        <th>Status</th>
        <th>Created</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each $apiKeys as k (k.id)}
        <tr>
          <td>{k.label}</td>
          <td class="monospace">{k.keyPrefix}...</td>
          <td class="monospace">{k.scopes.join(", ")}</td>
          <td>
            <span
              class="badge"
              class:badge-available={k.enabled}
              class:badge-unavailable={!k.enabled}
            >
              {k.enabled ? "active" : "revoked"}
            </span>
          </td>
          <td>{k.createdAt.slice(0, 10)}</td>
          <td>
            {#if k.enabled}
              <button class="btn btn-secondary" onclick={() => handleRevoke(k.id)}>Revoke</button>
            {/if}
          </td>
        </tr>
      {/each}
      {#if $apiKeys.length === 0}
        <tr><td colspan="6" class="empty">No API keys configured</td></tr>
      {/if}
    </tbody>
  </table>

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
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="modal-overlay" onclick={handleCloseModal}>
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div class="modal" onclick={(e) => e.stopPropagation()}>
        <h3>API Key Created</h3>
        <p class="modal-desc">Copy this key now — it will not be shown again.</p>
        <pre class="code-block key-value">{generatedKey}</pre>
        <div class="modal-actions">
          <button
            class="btn btn-primary"
            onclick={(e) => handleCopy(e.currentTarget as HTMLButtonElement)}>Copy</button
          >
          <button class="btn btn-secondary" onclick={handleCloseModal}>Done</button>
        </div>
      </div>
    </div>
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

  .monospace {
    font-family: monospace;
    font-size: 0.75rem;
  }

  .empty {
    color: #555;
  }

  .modal-desc {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0.75rem 0;
  }

  .modal-actions {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
    margin-top: 1rem;
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
