<script lang="ts">
  import { onMount } from "svelte";
  import Modal from "$lib/components/Modal.svelte";
  import {
    createEndpoint,
    deleteEndpoint,
    endpoints,
    ENDPOINT_DESCRIPTION_MAX_LENGTH,
    fetchEndpoints,
    updateEndpoint,
    USER_VERIFICATION_OPTIONS,
    type Endpoint,
    type UserVerification,
  } from "$lib/stores/endpoints.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import { formatEndpointAddress, parseEndpointAddress } from "$lib/utils/endpoint-address.js";
  import Wordmark from "$lib/components/Wordmark.svelte";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";

  type ModalMode = { kind: "create" } | { kind: "edit"; id: string };

  let modal = $state<ModalMode | null>(null);
  let saving = $state(false);
  let formLabel = $state("");
  let formAddress = $state("");
  let formUserVerification = $state<UserVerification>("required");
  let formDescription = $state("");

  onMount(() => {
    fetchEndpoints();
  });

  function openCreate() {
    modal = { kind: "create" };
    formLabel = "";
    formAddress = "";
    formUserVerification = "required";
    formDescription = "";
  }

  function openEdit(ep: Endpoint) {
    modal = { kind: "edit", id: ep.id };
    formLabel = ep.label;
    formAddress = formatEndpointAddress(ep);
    formUserVerification = ep.userVerification;
    formDescription = ep.description ?? "";
  }

  function closeModal() {
    if (saving) return;
    modal = null;
  }

  async function handleSave() {
    if (!modal || saving) return;
    if (!formLabel.trim() || !formAddress.trim()) {
      toastError("Label and Address are required");
      return;
    }
    let parsed;
    try {
      parsed = parseEndpointAddress(formAddress);
    } catch (err) {
      toastError(errorMessage(err));
      return;
    }
    const description = formDescription.trim() ? formDescription.trim() : null;
    saving = true;
    try {
      if (modal.kind === "create") {
        await createEndpoint({
          label: formLabel.trim(),
          host: parsed.host,
          port: parsed.port,
          username: parsed.username,
          userVerification: formUserVerification,
          description,
        });
      } else {
        await updateEndpoint(modal.id, {
          label: formLabel.trim(),
          host: parsed.host,
          port: parsed.port,
          username: parsed.username,
          userVerification: formUserVerification,
          description,
        });
      }
      modal = null;
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      saving = false;
    }
  }

  async function handleDelete(ep: Endpoint) {
    if (confirm(`Delete endpoint "${ep.label}"?`)) {
      try {
        await deleteEndpoint(ep.id);
      } catch (err) {
        toastError(errorMessage(err));
      }
    }
  }
</script>

<section>
  <div class="header">
    <h2>SSH Endpoints</h2>
    <button class="btn btn-primary" onclick={openCreate}>Add Endpoint</button>
  </div>

  <SettingsList empty={$endpoints.length === 0} emptyText="No endpoints configured">
    {#each $endpoints as ep (ep.id)}
      <SettingsRow detail={ep.description ?? null} detailLabel="Description">
        {#snippet primary()}
          <span class="row-label">{ep.label}</span>
          <span class="badge badge-available">{ep.userVerification}</span>
        {/snippet}
        {#snippet secondary()}{formatEndpointAddress(ep)}{/snippet}
        {#snippet actions()}
          <button class="btn btn-secondary" onclick={() => openEdit(ep)}>Edit</button>
          <button class="btn btn-secondary" onclick={() => handleDelete(ep)}>Delete</button>
        {/snippet}
      </SettingsRow>
    {/each}
  </SettingsList>

  <div class="hint-block">
    <p class="hint">
      <strong>User Verification</strong> controls the WebAuthn <code>userVerification</code> option
      used for passkey sign ceremonies to this endpoint. Defaults to <code>required</code> (PIN / biometric
      always enforced). Relax only if a specific authenticator can't provide UV.
    </p>
    <p class="hint">
      This is a <em>client-side</em> setting — <Wordmark /> requests UV from the authenticator and rejects
      responses without it when set to <code>required</code>, but the authoritative gate is the
      <strong>OpenSSH server</strong>. To make UV load-bearing, configure the target host to require
      it:
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

  {#if modal}
    <Modal
      title={modal.kind === "create" ? "Add Endpoint" : "Edit Endpoint"}
      onClose={closeModal}
      onSubmit={handleSave}
      width="520px"
    >
      <div class="field">
        <label for="ep-label">Label</label>
        <input id="ep-label" type="text" placeholder="My server" bind:value={formLabel} />
      </div>

      <div class="field">
        <label for="ep-address">Address</label>
        <input id="ep-address" type="text" placeholder="user@host:port" bind:value={formAddress} />
      </div>

      <div class="field">
        <label for="ep-uv">User Verification</label>
        <select id="ep-uv" bind:value={formUserVerification}>
          {#each USER_VERIFICATION_OPTIONS as opt (opt)}
            <option value={opt}>{opt}</option>
          {/each}
        </select>
      </div>

      <div class="field">
        <label for="ep-desc">
          Description <span class="field-hint">(optional, shown to MCP agents)</span>
        </label>
        <textarea
          id="ep-desc"
          rows="4"
          maxlength={ENDPOINT_DESCRIPTION_MAX_LENGTH}
          placeholder="e.g., production DB host, runs Postgres 15, /srv/data holds nightly dumps"
          bind:value={formDescription}
        ></textarea>
        <div class="char-count">{formDescription.length} / {ENDPOINT_DESCRIPTION_MAX_LENGTH}</div>
      </div>

      {#snippet actions()}
        <button type="button" class="btn btn-secondary" onclick={closeModal} disabled={saving}>
          Cancel
        </button>
        <button type="submit" class="btn btn-primary" disabled={saving}>
          {saving ? "Saving…" : modal?.kind === "create" ? "Add" : "Save"}
        </button>
      {/snippet}
    </Modal>
  {/if}
</section>

<style>
  h2 {
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
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

  .hint-block {
    margin-top: var(--space-6);
  }

  .hint {
    font-size: 0.8rem;
    color: var(--text-muted);
    line-height: 1.5;
  }

  .hint code {
    font-family: var(--font-mono);
    font-size: 0.85em;
    color: var(--primary);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    margin-top: 0.85rem;
  }

  .field label {
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .field-hint {
    font-weight: 400;
    text-transform: none;
    letter-spacing: 0;
    color: var(--text-muted);
  }

  .field select,
  .field textarea {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 0.5rem 0.75rem;
    border-radius: 4px;
    font-size: 0.9rem;
    font-family: inherit;
    width: 100%;
    box-sizing: border-box;
  }

  .field input {
    width: 100%;
    box-sizing: border-box;
  }

  .field textarea {
    resize: vertical;
    min-height: 4rem;
  }

  .field select:focus,
  .field textarea:focus {
    outline: none;
    border-color: var(--accent);
  }

  .char-count {
    font-size: 0.7rem;
    color: var(--text-muted);
    text-align: right;
  }
</style>
