<script lang="ts">
  import { onMount } from "svelte";
  import {
    createEndpoint,
    deleteEndpoint,
    endpoints,
    fetchEndpoints,
    updateEndpoint,
  } from "$lib/stores/endpoints.js";
  import { fetchSshKeys, sshKeys } from "$lib/stores/keys.js";
  import { formatEndpointAddress, parseEndpointAddress } from "$lib/utils/endpoint-address.js";

  let epLabel = $state("");
  let epAddress = $state("");
  let epKeyId = $state("");

  onMount(() => {
    fetchEndpoints();
    fetchSshKeys();
  });

  async function handleAdd() {
    if (!epLabel || !epAddress) {
      alert("Label and Address are required");
      return;
    }
    let parsed;
    try {
      parsed = parseEndpointAddress(epAddress);
    } catch (err) {
      alert((err as Error).message);
      return;
    }
    try {
      await createEndpoint({
        label: epLabel,
        host: parsed.host,
        port: parsed.port,
        username: parsed.username,
        keyId: epKeyId || undefined,
      });
      epLabel = "";
      epAddress = "";
      epKeyId = "";
    } catch (err) {
      alert((err as Error).message);
    }
  }

  async function handleKeyChange(id: string, keyId: string) {
    try {
      await updateEndpoint(id, { keyId: keyId || null });
    } catch (err) {
      alert((err as Error).message);
    }
  }

  async function handleDelete(id: string) {
    if (confirm(`Delete endpoint "${id}"?`)) {
      try {
        await deleteEndpoint(id);
      } catch (err) {
        alert((err as Error).message);
      }
    }
  }
</script>

<section>
  <h2>SSH Endpoints</h2>
  <table class="settings-table">
    <thead>
      <tr>
        <th>Label</th>
        <th>Address</th>
        <th>Key</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each $endpoints as ep (ep.id)}
        <tr>
          <td>{ep.label}</td>
          <td>{formatEndpointAddress(ep)}</td>
          <td>
            <select
              value={ep.keyId ?? ""}
              onchange={(e) => handleKeyChange(ep.id, e.currentTarget.value)}
            >
              {#if !ep.keyId}
                <option value="">No key</option>
              {/if}
              {#each $sshKeys as k (k.id)}
                <option value={k.id}>{k.label} ({k.type})</option>
              {/each}
            </select>
          </td>
          <td>
            <button class="btn btn-secondary" onclick={() => handleDelete(ep.id)}>Delete</button>
          </td>
        </tr>
      {/each}
      {#if $endpoints.length === 0}
        <tr><td colspan="4" class="empty">No endpoints configured</td></tr>
      {/if}
    </tbody>
  </table>

  <div class="settings-form">
    <h3>Add Endpoint</h3>
    <div class="form-row">
      <input type="text" placeholder="Label" bind:value={epLabel} />
      <input type="text" placeholder="user@host:port" bind:value={epAddress} />
      <select bind:value={epKeyId}>
        <option value="">No key</option>
        {#each $sshKeys as k (k.id)}
          <option value={k.id}>{k.label} ({k.type})</option>
        {/each}
      </select>
      <button class="btn btn-primary" onclick={handleAdd}>Add</button>
    </div>
  </div>
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

  .empty {
    color: #555;
  }
</style>
