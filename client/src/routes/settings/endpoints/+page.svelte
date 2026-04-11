<script lang="ts">
  import { onMount } from "svelte";
  import {
    createEndpoint,
    deleteEndpoint,
    endpoints,
    fetchEndpoints,
  } from "$lib/stores/endpoints.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import { formatEndpointAddress, parseEndpointAddress } from "$lib/utils/endpoint-address.js";

  let epLabel = $state("");
  let epAddress = $state("");

  onMount(() => {
    fetchEndpoints();
  });

  async function handleAdd() {
    if (!epLabel || !epAddress) {
      toastError("Label and Address are required");
      return;
    }
    let parsed;
    try {
      parsed = parseEndpointAddress(epAddress);
    } catch (err) {
      toastError(errorMessage(err));
      return;
    }
    try {
      await createEndpoint({
        label: epLabel,
        host: parsed.host,
        port: parsed.port,
        username: parsed.username,
      });
      epLabel = "";
      epAddress = "";
    } catch (err) {
      toastError(errorMessage(err));
    }
  }

  async function handleDelete(id: string) {
    if (confirm(`Delete endpoint "${id}"?`)) {
      try {
        await deleteEndpoint(id);
      } catch (err) {
        toastError(errorMessage(err));
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
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each $endpoints as ep (ep.id)}
        <tr>
          <td>{ep.label}</td>
          <td>{formatEndpointAddress(ep)}</td>
          <td>
            <button class="btn btn-secondary" onclick={() => handleDelete(ep.id)}>Delete</button>
          </td>
        </tr>
      {/each}
      {#if $endpoints.length === 0}
        <tr><td colspan="3" class="empty">No endpoints configured</td></tr>
      {/if}
    </tbody>
  </table>

  <div class="settings-form">
    <h3>Add Endpoint</h3>
    <div class="form-row">
      <input type="text" placeholder="Label" bind:value={epLabel} />
      <input type="text" placeholder="user@host:port" bind:value={epAddress} />
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
