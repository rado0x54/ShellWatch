<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import Modal from "$lib/components/Modal.svelte";
  import ConfirmDialog from "$lib/components/ConfirmDialog.svelte";
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
  let formAgentForward = $state(true);
  let formDescription = $state("");
  let deleteTarget = $state<Endpoint | null>(null);
  let deleting = $state(false);

  onMount(() => {
    fetchEndpoints();
  });

  function openCreate() {
    modal = { kind: "create" };
    formLabel = "";
    formAddress = "";
    formUserVerification = "required";
    formAgentForward = true;
    formDescription = "";
  }

  function openEdit(ep: Endpoint) {
    modal = { kind: "edit", id: ep.id };
    formLabel = ep.label;
    formAddress = formatEndpointAddress(ep);
    formUserVerification = ep.userVerification;
    formAgentForward = ep.agentForward;
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
          agentForward: formAgentForward,
          description,
        });
      } else {
        await updateEndpoint(modal.id, {
          label: formLabel.trim(),
          host: parsed.host,
          port: parsed.port,
          username: parsed.username,
          userVerification: formUserVerification,
          agentForward: formAgentForward,
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

  function openDelete(ep: Endpoint) {
    deleteTarget = ep;
  }

  function closeDelete() {
    if (deleting) return;
    deleteTarget = null;
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    deleting = true;
    try {
      await deleteEndpoint(deleteTarget.id);
      deleteTarget = null;
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      deleting = false;
    }
  }
</script>

<section>
  <div class="header">
    <h2>SSH Endpoints</h2>
    <button type="button" class="btn btn-primary" onclick={openCreate}>Add Endpoint</button>
  </div>

  <SettingsList empty={$endpoints.length === 0} emptyText="No endpoints configured">
    {#each $endpoints as ep (ep.id)}
      <SettingsRow detail={ep.description ?? null} detailLabel="Description">
        {#snippet primary()}
          <span class="row-label">{ep.label}</span>
          <span class="badge badge-available">UV: {ep.userVerification}</span>
          <span class="badge" class:badge-available={ep.agentForward}>
            forward: {ep.agentForward ? "on" : "off"}
          </span>
        {/snippet}
        {#snippet secondary()}{formatEndpointAddress(ep)}{/snippet}
        {#snippet actions()}
          <button type="button" class="btn btn-secondary" onclick={() => openEdit(ep)}>Edit</button>
          <button type="button" class="btn btn-secondary" onclick={() => openDelete(ep)}
            >Delete</button
          >
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

  {#if deleteTarget}
    <ConfirmDialog
      title="Delete endpoint?"
      confirmLabel="Delete"
      onConfirm={handleDelete}
      onCancel={closeDelete}
      processing={deleting}
    >
      <p class="modal-desc">
        Delete <strong>{deleteTarget.label}</strong> ({formatEndpointAddress(deleteTarget)})? Open
        sessions to this endpoint won't be torn down, but no new ones can be opened.
      </p>
    </ConfirmDialog>
  {/if}

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

      <div class="field">
        <label for="ep-agent-forward">SSH Agent Forwarding</label>
        <div class="toggle-row">
          <button
            type="button"
            id="ep-agent-forward"
            class="toggle"
            class:active={formAgentForward}
            onclick={() => (formAgentForward = !formAgentForward)}
            aria-label="SSH Agent Forwarding"
            role="switch"
            aria-checked={formAgentForward}
          >
            <span class="toggle-knob"></span>
          </button>
          <span class="toggle-label">{formAgentForward ? "Enabled" : "Disabled"}</span>
        </div>
        <span class="field-help">
          Forward SSH keys to this host so onward tools (ssh, git) can authenticate.
        </span>
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

  .field-help {
    display: block;
    margin-top: 0.4rem;
    font-size: 0.75rem;
    color: var(--text-muted);
    line-height: 1.5;
  }

  .toggle-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .toggle {
    position: relative;
    width: 40px;
    height: 22px;
    border-radius: 11px;
    border: 1px solid var(--border);
    background: var(--bg-primary);
    cursor: pointer;
    padding: 0;
    transition: background-color 0.2s;
  }

  .toggle.active {
    background: var(--green, #4ade80);
    border-color: var(--green, #4ade80);
  }

  .toggle-knob {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--text-muted);
    transition:
      transform 0.2s,
      background-color 0.2s;
  }

  .toggle.active .toggle-knob {
    transform: translateX(18px);
    background: white;
  }

  .toggle-label {
    font-size: 0.85rem;
    color: var(--text-primary);
  }

  .field textarea {
    resize: vertical;
    min-height: 4rem;
  }

  .char-count {
    font-size: 0.7rem;
    color: var(--text-muted);
    text-align: right;
  }

  .modal-desc {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0 0 var(--space-3);
    line-height: 1.5;
  }
</style>
