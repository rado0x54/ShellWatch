<script lang="ts">
  import { onMount } from "svelte";
  import {
    createEndpoint,
    deleteEndpoint,
    endpoints,
    fetchEndpoints,
  } from "$lib/stores/endpoints.js";
  import { fetchSshKeys, sshKeys } from "$lib/stores/keys.js";

  let epId = $state("");
  let epLabel = $state("");
  let epHost = $state("");
  let epPort = $state(22);
  let epUsername = $state("");
  let epKeyId = $state("");

  onMount(() => {
    fetchEndpoints();
    fetchSshKeys();
  });

  async function handleAdd() {
    if (!epId || !epLabel || !epHost || !epUsername) {
      alert("ID, Label, Host, and Username are required");
      return;
    }
    try {
      await createEndpoint({
        id: epId,
        label: epLabel,
        host: epHost,
        port: epPort,
        username: epUsername,
        keyId: epKeyId || undefined,
      });
      epId = "";
      epLabel = "";
      epHost = "";
      epPort = 22;
      epUsername = "";
      epKeyId = "";
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
        <th>ID</th>
        <th>Label</th>
        <th>Host</th>
        <th>Port</th>
        <th>Username</th>
        <th>Key</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each $endpoints as ep (ep.id)}
        <tr>
          <td>{ep.id}</td>
          <td>{ep.label}</td>
          <td>{ep.host}</td>
          <td>{ep.port}</td>
          <td>{ep.username}</td>
          <td>{ep.keyId ?? "\u2014"}</td>
          <td>
            <button class="btn btn-secondary" onclick={() => handleDelete(ep.id)}>Delete</button>
          </td>
        </tr>
      {/each}
      {#if $endpoints.length === 0}
        <tr><td colspan="7" class="empty">No endpoints configured</td></tr>
      {/if}
    </tbody>
  </table>

  <div class="settings-form">
    <h3>Add Endpoint</h3>
    <div class="form-row">
      <input type="text" placeholder="ID" bind:value={epId} />
      <input type="text" placeholder="Label" bind:value={epLabel} />
      <input type="text" placeholder="Host" bind:value={epHost} />
      <input type="number" placeholder="Port" bind:value={epPort} />
      <input type="text" placeholder="Username" bind:value={epUsername} />
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
