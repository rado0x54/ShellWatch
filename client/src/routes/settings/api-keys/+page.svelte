<script lang="ts">
import { onMount } from "svelte";
import { apiKeys, fetchApiKeys, generateApiKey, revokeApiKey } from "$lib/stores/keys.js";

let label = $state("");
let showKeyModal = $state(false);
let generatedKey = $state("");

onMount(() => {
  fetchApiKeys();
});

async function handleGenerate() {
  if (!label.trim()) return;
  try {
    generatedKey = await generateApiKey(label.trim());
    showKeyModal = true;
    label = "";
  } catch (err) {
    alert((err as Error).message);
  }
}

async function handleRevoke(id: string) {
  if (confirm("Revoke this API key?")) {
    await revokeApiKey(id);
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
  <h2>API Keys (MCP)</h2>
  <table class="settings-table">
    <thead>
      <tr>
        <th>Label</th>
        <th>Prefix</th>
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
          <td>
            <span class="badge" class:badge-available={k.enabled} class:badge-unavailable={!k.enabled}>
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
        <tr><td colspan="5" class="empty">No API keys configured</td></tr>
      {/if}
    </tbody>
  </table>

  <div class="settings-form">
    <h3>Generate API Key</h3>
    <div class="form-row">
      <input type="text" placeholder="Label (e.g., Claude Agent)" bind:value={label} style="flex: 1" />
      <button class="btn btn-primary" onclick={handleGenerate}>Generate</button>
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
          <button class="btn btn-primary" onclick={(e) => handleCopy(e.currentTarget as HTMLButtonElement)}>Copy</button>
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
</style>
