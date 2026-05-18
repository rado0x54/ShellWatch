<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import Modal from "$lib/components/Modal.svelte";
  import ConfirmDialog from "$lib/components/ConfirmDialog.svelte";
  import ServerSetupGuide from "$lib/components/ServerSetupGuide.svelte";
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
  import { account, fetchAccount, updateShowDemoEndpoints } from "$lib/stores/account.js";
  import { credentials, fetchCredentials } from "$lib/stores/webauthn.js";
  import { toastError } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import { formatEndpointAddress, parseEndpointAddress } from "$lib/utils/endpoint-address.js";
  import SettingsList from "$lib/components/SettingsList.svelte";
  import SettingsRow from "$lib/components/SettingsRow.svelte";

  // The wizard kinds prefix the form with a Server-Setup primer. Triggered
  // automatically when the user clicks Add Endpoint while they have no own
  // endpoints yet — the button label itself is static.
  type ModalMode =
    | { kind: "create" }
    | { kind: "edit"; id: string }
    | { kind: "wizard-server" }
    | { kind: "wizard-form" };

  let modal = $state<ModalMode | null>(null);
  let saving = $state(false);
  let formLabel = $state("");
  let formAddress = $state("");
  let formUserVerification = $state<UserVerification>("required");
  let formAgentForward = $state(true);
  let formDescription = $state("");
  let deleteTarget = $state<Endpoint | null>(null);
  let deleting = $state(false);
  let togglingDemo = $state(false);
  // Tracks whether the Address field has been blurred. Used to surface the
  // "user defaults to shellwatch" hint only after the user finishes editing —
  // we don't want it nagging mid-typing.
  let addressBlurred = $state(false);

  // The default-user affordance fires when the user blurred away from a
  // non-empty address that has no `user@` prefix. The actual prefix is shown
  // as a gray adornment next to the input; the value in the input stays as
  // whatever the user typed (parseEndpointAddress applies the default).
  const showDefaultUserHint = $derived(
    addressBlurred && formAddress.length > 0 && !formAddress.includes("@"),
  );

  // Split the merged endpoint list so we can render demos in their own
  // section below the user's own endpoints. The server only returns demo
  // entries when account.showDemoEndpoints is on, so this filter is empty
  // when the toggle is off.
  const regularEndpoints = $derived($endpoints.filter((ep) => !ep.isDemo));
  const demoEndpoints = $derived($endpoints.filter((ep) => ep.isDemo));

  // First active passkey that's convertible to SSH — used by the wizard's
  // Server-Setup step so the authorized_keys command is fully copy-pastable.
  const wizardPasskey = $derived(
    $credentials.find((c) => c.state === "active" && c.authorizedKeysEntry !== null) ?? null,
  );

  // The form modal is the same shape for create / wizard-form / edit. Only the
  // Back button (wizard) vs Cancel (everywhere else) and the submit handler's
  // create-vs-update branch differ.
  const isFormModal = $derived(
    modal?.kind === "create" || modal?.kind === "edit" || modal?.kind === "wizard-form",
  );

  function modalTitle(m: ModalMode): string {
    switch (m.kind) {
      case "create":
      case "wizard-form":
        return "Add Endpoint";
      case "edit":
        return "Edit Endpoint";
      case "wizard-server":
        return "Set up your SSH server";
    }
  }

  onMount(() => {
    fetchEndpoints();
    fetchAccount();
    fetchCredentials();
  });

  async function handleToggleDemo() {
    if (togglingDemo || !$account) return;
    togglingDemo = true;
    try {
      await updateShowDemoEndpoints(!$account.showDemoEndpoints);
      await fetchEndpoints();
    } catch (err) {
      toastError(errorMessage(err));
    } finally {
      togglingDemo = false;
    }
  }

  function resetForm() {
    formLabel = "";
    formAddress = "";
    formUserVerification = "required";
    formAgentForward = true;
    formDescription = "";
    addressBlurred = false;
  }

  // Single entry point from the Add Endpoint button. When the user has no own
  // endpoints yet we lead with the SSH-server setup primer; otherwise we drop
  // straight into the form — the button label stays the same either way.
  function openAdd() {
    resetForm();
    modal = regularEndpoints.length === 0 ? { kind: "wizard-server" } : { kind: "create" };
  }

  function continueWizard() {
    modal = { kind: "wizard-form" };
  }

  function wizardBack() {
    modal = { kind: "wizard-server" };
  }

  function openEdit(ep: Endpoint) {
    modal = { kind: "edit", id: ep.id };
    formLabel = ep.label;
    formAddress = formatEndpointAddress(ep);
    formUserVerification = ep.userVerification;
    formAgentForward = ep.agentForward;
    formDescription = ep.description ?? "";
    addressBlurred = false;
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
      if (modal.kind === "edit") {
        await updateEndpoint(modal.id, {
          label: formLabel.trim(),
          host: parsed.host,
          port: parsed.port,
          username: parsed.username,
          userVerification: formUserVerification,
          agentForward: formAgentForward,
          description,
        });
      } else {
        // create or wizard-form — both POST a new endpoint
        await createEndpoint({
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
  <h2>SSH Endpoints</h2>

  <SettingsList empty={regularEndpoints.length === 0} emptyText="No endpoints configured">
    {#each regularEndpoints as ep (ep.id)}
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

  <div class="register-section">
    <button type="button" class="btn btn-primary" onclick={openAdd}>Add Endpoint</button>
  </div>

  {#if $account?.demoEndpointsAvailable}
    <div class="demo-section-header">
      <h3 class="demo-section-label">Demo Endpoints</h3>
      <button
        type="button"
        class="toggle"
        class:active={$account.showDemoEndpoints}
        onclick={handleToggleDemo}
        disabled={togglingDemo}
        aria-label="Show demo endpoints"
        role="switch"
        aria-checked={$account.showDemoEndpoints}
      >
        <span class="toggle-knob"></span>
      </button>
      <span class="toggle-label">Show</span>
    </div>

    {#if $account.showDemoEndpoints}
      <SettingsList
        empty={demoEndpoints.length === 0}
        emptyText="No demo endpoints configured by the operator"
      >
        {#each demoEndpoints as ep (ep.id)}
          <SettingsRow detail={ep.description ?? null} detailLabel="Description">
            {#snippet primary()}
              <span class="row-label">{ep.label}</span>
              <span class="badge badge-available">UV: {ep.userVerification}</span>
              <span class="badge" class:badge-available={ep.agentForward}>
                forward: {ep.agentForward ? "on" : "off"}
              </span>
            {/snippet}
            {#snippet secondary()}{formatEndpointAddress(ep)}{/snippet}
          </SettingsRow>
        {/each}
      </SettingsList>
    {/if}
  {/if}

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

  {#if modal && modal.kind === "wizard-server"}
    <Modal title={modalTitle(modal)} onClose={closeModal} width="520px">
      <p class="wizard-step-hint">Step 1 of 2 · Server setup</p>
      <p class="modal-desc">
        Before adding your first endpoint, set up the remote server to accept your <strong
          >ShellWatch</strong
        > passkey credential.
      </p>
      <ServerSetupGuide passkey={wizardPasskey} accountName={$account?.name} />

      {#snippet actions()}
        <button type="button" class="btn btn-secondary" onclick={closeModal}>Cancel</button>
        <button type="button" class="btn btn-primary" onclick={continueWizard}>Continue</button>
      {/snippet}
    </Modal>
  {/if}

  {#if modal && isFormModal}
    <Modal title={modalTitle(modal)} onClose={closeModal} onSubmit={handleSave} width="520px">
      {#if modal.kind === "wizard-form"}
        <p class="wizard-step-hint">Step 2 of 2 · Endpoint details</p>
      {/if}

      <div class="field">
        <label for="ep-label">Label</label>
        <input id="ep-label" type="text" placeholder="My server" bind:value={formLabel} />
      </div>

      <div class="field">
        <label for="ep-address">Address</label>
        <div class="address-input-wrap" class:has-default-user={showDefaultUserHint}>
          {#if showDefaultUserHint}
            <span class="default-user-prefix">shellwatch@</span>
          {/if}
          <input
            id="ep-address"
            type="text"
            placeholder="user@host:port"
            bind:value={formAddress}
            onfocus={() => (addressBlurred = false)}
            onblur={() => (addressBlurred = true)}
          />
        </div>
        {#if showDefaultUserHint}
          <span class="address-warning"
            >User defaults to <code>shellwatch</code> if not specified.</span
          >
        {/if}
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
        {#if modal?.kind === "wizard-form"}
          <button type="button" class="btn btn-secondary" onclick={wizardBack} disabled={saving}>
            Back
          </button>
        {:else}
          <button type="button" class="btn btn-secondary" onclick={closeModal} disabled={saving}>
            Cancel
          </button>
        {/if}
        <button type="submit" class="btn btn-primary" disabled={saving}>
          {saving ? "Saving…" : modal?.kind === "edit" ? "Save" : "Add"}
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

  .register-section {
    margin-top: var(--space-5);
    display: flex;
    align-items: center;
    gap: var(--space-3);
    flex-wrap: wrap;
  }

  /* Demo Endpoints section: headline + toggle clustered on the left so it
     matches the rest of the settings pages where actions live left-aligned. */
  .demo-section-header {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-top: var(--space-6);
    margin-bottom: 0.75rem;
    padding-top: var(--space-4);
    border-top: 1px solid var(--border);
  }

  .demo-section-label {
    margin: 0;
    font-size: 0.75rem;
    font-weight: 600;
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

  .wizard-step-hint {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin: 0 0 0.75rem;
  }

  /* Address input with an optional gray "shellwatch@" prefix adornment shown
     after blur when the user didn't supply a custom username. The wrapper
     mimics the input's chrome so the prefix + input look like one field. */
  .address-input-wrap {
    display: flex;
    align-items: stretch;
    width: 100%;
  }

  .address-input-wrap.has-default-user {
    border: 1px solid var(--outline-variant);
    border-radius: 6px;
    background-color: var(--surface-container);
    overflow: hidden;
  }

  .address-input-wrap.has-default-user input {
    border: none;
    background: transparent;
    padding-left: 0;
  }

  .default-user-prefix {
    display: inline-flex;
    align-items: center;
    padding: 0.5rem 0 0.5rem 0.625rem;
    color: var(--text-muted);
    font-family: var(--font-mono, monospace);
    font-size: var(--body-md);
    user-select: none;
    pointer-events: none;
  }

  .address-warning {
    display: block;
    margin-top: 0.35rem;
    font-size: 0.75rem;
    color: var(--warning, var(--secondary, #f59e0b));
    line-height: 1.4;
  }

  .address-warning code {
    font-family: var(--font-mono);
    font-size: 0.85em;
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
