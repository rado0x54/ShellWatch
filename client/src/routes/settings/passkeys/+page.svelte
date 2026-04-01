<script lang="ts">
import { onMount } from "svelte";
import {
  credentials,
  deleteCredential,
  fetchCredentials,
  finishPasskeyRegistration,
  startPasskeyRegistration,
} from "$lib/stores/webauthn.js";

let showModal = $state(false);
let modalLabel = $state("");
let modalDesc = $state("");
let pendingRegistration: {
  challengeId: string;
  credential: Parameters<typeof finishPasskeyRegistration>[1];
  suggestedLabel: string;
} | null = null;

onMount(() => {
  fetchCredentials();
});

function copyKey(key: string, btn: HTMLButtonElement) {
  navigator.clipboard.writeText(key);
  const original = btn.textContent;
  btn.textContent = "Copied!";
  setTimeout(() => {
    btn.textContent = original;
  }, 1500);
}

async function handleDelete(id: string) {
  if (confirm("Delete this passkey?")) {
    await deleteCredential(id);
  }
}

async function handleRegister() {
  try {
    const result = await startPasskeyRegistration();
    pendingRegistration = result;
    modalLabel = result.suggestedLabel;
    modalDesc = `Detected: ${result.suggestedLabel}. Change the label if you like.`;
    showModal = true;
  } catch (err) {
    alert(`Registration failed: ${(err as Error).message}`);
  }
}

async function handleSave() {
  if (!pendingRegistration) return;
  const label = modalLabel.trim() || pendingRegistration.suggestedLabel;
  try {
    await finishPasskeyRegistration(
      pendingRegistration.challengeId,
      pendingRegistration.credential,
      label,
    );
  } catch (err) {
    alert(`Registration failed: ${(err as Error).message}`);
  }
  showModal = false;
  pendingRegistration = null;
}

function handleCancel() {
  showModal = false;
  pendingRegistration = null;
}

function handleModalKeydown(e: KeyboardEvent) {
  if (e.key === "Enter") handleSave();
  if (e.key === "Escape") handleCancel();
}

const hasAuthorizedKeys = $derived($credentials.some((pk) => pk.authorizedKeysEntry));
</script>

<section>
  <h2>Passkeys (WebAuthn)</h2>
  <table class="settings-table">
    <thead>
      <tr>
        <th>Label</th>
        <th>Algorithm</th>
        <th>Fingerprint</th>
        <th>Created</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each $credentials as pk (pk.id)}
        <tr>
          <td>{pk.label}</td>
          <td>{pk.algorithm}</td>
          <td class="fingerprint">{pk.fingerprint.slice(0, 25)}...</td>
          <td>{pk.createdAt.slice(0, 10)}</td>
          <td class="actions">
            {#if pk.authorizedKeysEntry}
              <button
                class="btn-copy"
                onclick={(e) => copyKey(pk.authorizedKeysEntry!, e.currentTarget as HTMLButtonElement)}
              >Copy SSH Key</button>
            {/if}
            <button class="btn btn-secondary" onclick={() => handleDelete(pk.id)}>Delete</button>
          </td>
        </tr>
      {/each}
      {#if $credentials.length === 0}
        <tr><td colspan="5" class="empty">No passkeys registered</td></tr>
      {/if}
    </tbody>
  </table>

  {#if hasAuthorizedKeys}
    <div class="settings-info">
      <h3>SSH Server Setup</h3>
      <p>Add this line to <code>/etc/ssh/sshd_config</code> on your remote server:</p>
      <pre class="code-block">PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com</pre>
      <p>Then add the passkey's SSH public key to <code>~/.ssh/authorized_keys</code>.</p>
    </div>
  {/if}

  <div class="register-section">
    <button class="btn btn-primary" onclick={handleRegister}>Register New Passkey</button>
  </div>

  {#if showModal}
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="modal-overlay" onclick={handleCancel}>
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div class="modal" onclick={(e) => e.stopPropagation()}>
        <h3>Name Your Passkey</h3>
        <p class="modal-desc">{modalDesc}</p>
        <!-- svelte-ignore a11y_autofocus -->
        <input
          type="text"
          bind:value={modalLabel}
          placeholder="e.g., YubiKey 5 NFC"
          onkeydown={handleModalKeydown}
          autofocus
          style="width: 100%; margin-bottom: 1rem"
        />
        <div class="modal-actions">
          <button class="btn btn-secondary" onclick={handleCancel}>Cancel</button>
          <button class="btn btn-primary" onclick={handleSave}>Save</button>
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

  .fingerprint {
    font-family: monospace;
    font-size: 0.75rem;
  }

  .actions {
    display: flex;
    gap: 0.25rem;
    align-items: center;
  }

  .btn-copy {
    background: none;
    border: 1px solid var(--border);
    color: var(--text-muted);
    padding: 0.2rem 0.4rem;
    border-radius: 3px;
    font-size: 0.65rem;
    cursor: pointer;
  }

  .btn-copy:hover {
    border-color: var(--accent);
    color: var(--accent);
  }

  .empty {
    color: #555;
  }

  .register-section {
    margin-top: 1rem;
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
  }
</style>
