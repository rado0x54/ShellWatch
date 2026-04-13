<script lang="ts">
  import { onMount } from "svelte";
  import {
    createEndpoint,
    deleteEndpoint,
    endpoints,
    ENDPOINT_DESCRIPTION_MAX_LENGTH,
    fetchEndpoints,
    updateEndpoint,
    USER_VERIFICATION_OPTIONS,
    type UserVerification,
  } from "$lib/stores/endpoints.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import { formatEndpointAddress, parseEndpointAddress } from "$lib/utils/endpoint-address.js";

  let epLabel = $state("");
  let epAddress = $state("");
  let epUserVerification = $state<UserVerification>("required");
  let epDescription = $state("");
  let descriptionDrafts = $state<Record<string, string>>({});

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
        userVerification: epUserVerification,
        description: epDescription.trim() ? epDescription : null,
      });
      epLabel = "";
      epAddress = "";
      epUserVerification = "required";
      epDescription = "";
    } catch (err) {
      toastError(errorMessage(err));
    }
  }

  async function handleUserVerificationChange(id: string, value: UserVerification) {
    try {
      await updateEndpoint(id, { userVerification: value });
    } catch (err) {
      toastError(errorMessage(err));
    }
  }

  async function handleDescriptionSave(id: string, original: string | null) {
    const draft = descriptionDrafts[id] ?? "";
    const next = draft.trim() ? draft : null;
    if (next === (original ?? null)) return;
    try {
      await updateEndpoint(id, { description: next });
      delete descriptionDrafts[id];
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
        <th>User Verification</th>
        <th>Description</th>
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
              value={ep.userVerification}
              onchange={(e) =>
                handleUserVerificationChange(
                  ep.id,
                  (e.currentTarget as HTMLSelectElement).value as UserVerification,
                )}
            >
              {#each USER_VERIFICATION_OPTIONS as opt (opt)}
                <option value={opt}>{opt}</option>
              {/each}
            </select>
          </td>
          <td>
            <textarea
              class="desc-input"
              rows="2"
              maxlength={ENDPOINT_DESCRIPTION_MAX_LENGTH}
              placeholder="Optional context shown to MCP agents"
              value={descriptionDrafts[ep.id] ?? ep.description ?? ""}
              oninput={(e) =>
                (descriptionDrafts[ep.id] = (e.currentTarget as HTMLTextAreaElement).value)}
              onblur={() => handleDescriptionSave(ep.id, ep.description)}
            ></textarea>
          </td>
          <td>
            <button class="btn btn-secondary" onclick={() => handleDelete(ep.id)}>Delete</button>
          </td>
        </tr>
      {/each}
      {#if $endpoints.length === 0}
        <tr><td colspan="5" class="empty">No endpoints configured</td></tr>
      {/if}
    </tbody>
  </table>

  <div class="settings-form">
    <h3>Add Endpoint</h3>
    <div class="form-row">
      <input type="text" placeholder="Label" bind:value={epLabel} />
      <input type="text" placeholder="user@host:port" bind:value={epAddress} />
      <select bind:value={epUserVerification}>
        {#each USER_VERIFICATION_OPTIONS as opt (opt)}
          <option value={opt}>UV: {opt}</option>
        {/each}
      </select>
      <button class="btn btn-primary" onclick={handleAdd}>Add</button>
    </div>
    <div class="form-row">
      <textarea
        class="desc-input desc-input-add"
        rows="2"
        maxlength={ENDPOINT_DESCRIPTION_MAX_LENGTH}
        placeholder="Description (optional, shown to MCP agents on connect)"
        bind:value={epDescription}
      ></textarea>
    </div>
    <p class="hint">
      <strong>User Verification</strong> controls the WebAuthn <code>userVerification</code> option
      used for passkey sign ceremonies to this endpoint. Defaults to <code>required</code> (PIN / biometric
      always enforced). Relax only if a specific authenticator can't provide UV.
    </p>
    <p class="hint">
      This is a <em>client-side</em> setting — ShellWatch requests UV from the authenticator and
      rejects responses without it when set to <code>required</code>, but the authoritative gate is
      the <strong>OpenSSH server</strong>. To make UV load-bearing, configure the target host to
      require it:
    </p>
    <ul class="hint">
      <li>
        <strong>Globally</strong> in <code>sshd_config</code>:
        <code>PubkeyAuthOptions verify-required</code>
      </li>
      <li>
        <strong>Per-key</strong> in <code>~/.ssh/authorized_keys</code> on the server:
        <code>verify-required sk-ecdsa-sha2-nistp256@openssh.com AAAA... user@host</code>
      </li>
    </ul>
    <p class="hint">
      Either source enables enforcement; <code>sshd</code> rejects signatures without the UV bit (<code
        >SSH_SK_USER_VERIFICATION_REQD</code
      >, <code>0x04</code>) set, logging
      <code>user verification requirement not met</code>. See the project README for details.
    </p>
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

  .hint {
    margin-top: 0.75rem;
    font-size: 0.8rem;
    color: var(--text-muted);
    line-height: 1.5;
  }

  .hint code {
    font-family: monospace;
    font-size: 0.85em;
  }

  .desc-input {
    width: 100%;
    min-width: 12rem;
    font: inherit;
    resize: vertical;
  }

  .desc-input-add {
    flex: 1;
  }
</style>
