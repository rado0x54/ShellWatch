<script lang="ts">
  import { onMount } from "svelte";
  import { account } from "$lib/stores/account.js";
  import {
    createEndpoint,
    deleteEndpoint,
    endpoints,
    fetchEndpoints,
    updateEndpoint,
  } from "$lib/stores/endpoints.js";
  import { fetchSshKeys, sshKeys } from "$lib/stores/keys.js";
  import { credentials, fetchCredentials } from "$lib/stores/webauthn.js";
  import { formatEndpointAddress, parseEndpointAddress } from "$lib/utils/endpoint-address.js";

  let epLabel = $state("");
  let epAddress = $state("");
  let epKeyValue = $state("");

  onMount(() => {
    fetchEndpoints();
    fetchSshKeys();
    fetchCredentials();
  });

  /** Parse a combined key value like "file:key-1" or "passkey:cred-1" */
  function parseKeyValue(value: string): { keyId?: string; passkeyId?: string } {
    if (!value) return {};
    if (value.startsWith("passkey:")) return { passkeyId: value.slice(8) };
    return { keyId: value.startsWith("file:") ? value.slice(5) : value };
  }

  /** Build a combined key value from an endpoint's keyId/passkeyId */
  function buildKeyValue(ep: { keyId?: string | null; passkeyId?: string | null }): string {
    if (ep.passkeyId) return `passkey:${ep.passkeyId}`;
    if (ep.keyId) return `file:${ep.keyId}`;
    return "";
  }

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
      const keySelection = parseKeyValue(epKeyValue);
      await createEndpoint({
        label: epLabel,
        host: parsed.host,
        port: parsed.port,
        username: parsed.username,
        ...keySelection,
      });
      epLabel = "";
      epAddress = "";
      epKeyValue = "";
    } catch (err) {
      alert((err as Error).message);
    }
  }

  async function handleKeyChange(id: string, value: string) {
    try {
      const selection = parseKeyValue(value);
      await updateEndpoint(id, {
        keyId: selection.keyId ?? null,
        passkeyId: selection.passkeyId ?? null,
      });
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

  const activePasskeys = $derived($credentials.filter((c) => !c.revoked));
  const isAdmin = $derived($account?.isAdmin ?? false);
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
              value={buildKeyValue(ep)}
              onchange={(e) => handleKeyChange(ep.id, e.currentTarget.value)}
            >
              <option value="">Auto (negotiate)</option>
              {#if isAdmin}
                {#each $sshKeys as k (k.id)}
                  <option value="file:{k.id}">{k.label} (file)</option>
                {/each}
              {/if}
              {#each activePasskeys as c (c.id)}
                <option value="passkey:{c.id}">{c.label} (passkey)</option>
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
      <select bind:value={epKeyValue}>
        <option value="">Auto (negotiate)</option>
        {#if isAdmin}
          {#each $sshKeys as k (k.id)}
            <option value="file:{k.id}">{k.label} (file)</option>
          {/each}
        {/if}
        {#each activePasskeys as c (c.id)}
          <option value="passkey:{c.id}">{c.label} (passkey)</option>
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
