<script lang="ts">
  import { onMount } from "svelte";
  import { page } from "$app/state";
  import { fetchInviteByToken, registerWithInviteToken } from "$lib/stores/webauthn.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import Wordmark from "$lib/components/Wordmark.svelte";

  type LocalState = "loading" | "ready" | "registering" | "done" | "unavailable" | "error";

  let local = $state<LocalState>("loading");
  let suggestedLabel = $state("");
  let labelInput = $state("");
  let assignedLabel = $state("");
  let assignedFingerprint = $state<string | null>(null);
  let expiresAt = $state("");
  let error = $state("");

  const token = $derived(page.params.token ?? "");

  onMount(async () => {
    if (!token) {
      local = "error";
      error = "Missing invite token";
      return;
    }
    try {
      // Server returns the slot only when it's still active; expired or
      // already-consumed slots come back as 404 from the in-memory store and
      // surface here as a thrown error.
      const info = await fetchInviteByToken(token);
      suggestedLabel = info.label;
      labelInput = info.label;
      expiresAt = info.expiresAt;
      local = "ready";
    } catch {
      local = "unavailable";
    }
  });

  async function handleRegister() {
    if (!token) return;
    local = "registering";
    error = "";
    try {
      const result = await registerWithInviteToken({
        token,
        label: labelInput.trim() || undefined,
      });
      assignedLabel = result.label;
      assignedFingerprint = result.fingerprint;
      local = "done";
    } catch (err) {
      error = errorMessage(err);
      local = "ready";
    }
  }

  function formatTimeLeft(iso: string): string {
    const ms = Date.parse(iso) - Date.now();
    if (ms <= 0) return "expired";
    const mins = Math.round(ms / 60_000);
    if (mins < 60) return `${mins} minutes`;
    const hours = Math.round(mins / 60);
    return `${hours} hours`;
  }
</script>

<div class="invite-page">
  <div class="invite-card">
    <h1>Add a passkey to <Wordmark /></h1>

    {#if local === "loading"}
      <p class="status">Loading invite…</p>
    {:else if local === "ready"}
      <p class="description">
        You've been invited to enroll a new passkey on this device. Once you register here, the
        device that issued this invite will need to confirm it before the passkey becomes usable.
      </p>
      <p class="meta">Expires in {formatTimeLeft(expiresAt)}</p>
      <label class="field">
        <span class="field-label">Name this passkey</span>
        <input
          class="input"
          type="text"
          bind:value={labelInput}
          placeholder={suggestedLabel}
          maxlength="64"
        />
      </label>
      <button class="btn-primary" onclick={handleRegister}>Register passkey</button>
      {#if error}
        <p class="error">{error}</p>
      {/if}
    {:else if local === "registering"}
      <p class="status">Waiting for your authenticator…</p>
    {:else if local === "done"}
      <p class="description">
        <span class="check">✓</span> Passkey <strong>{assignedLabel}</strong> registered. Go back to
        your other device and click <strong>Confirm</strong> to activate it. Until then, the passkey cannot
        be used to log in or sign anything.
      </p>
      {#if assignedFingerprint}
        <div class="fingerprint-card">
          <span class="fingerprint-label">Fingerprint</span>
          <code class="fingerprint-value">{assignedFingerprint}</code>
          <p class="fingerprint-help">
            Verify this string matches the fingerprint shown on the original device before you
            confirm there. They will be identical if the passkey was registered on the right invite.
          </p>
        </div>
      {/if}
    {:else if local === "unavailable"}
      <p class="description">
        This invite has expired or already been used. Ask the inviter to issue a new one.
      </p>
    {:else}
      <p class="error">{error || "Could not load this invite"}</p>
    {/if}
  </div>
</div>

<style>
  .invite-page {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-primary);
    padding: 1rem;
    box-sizing: border-box;
  }

  .invite-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem;
    text-align: center;
    max-width: 480px;
    width: 100%;
    box-sizing: border-box;
  }

  h1 {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
  }

  .description {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-bottom: 0.75rem;
    line-height: 1.55;
  }

  .meta {
    font-size: 0.78rem;
    color: var(--text-muted);
    margin-bottom: 1rem;
  }

  .status {
    color: var(--text-muted);
    font-size: 0.85rem;
  }

  .check {
    color: var(--green, #4ade80);
    font-weight: 600;
    margin-right: 0.25rem;
  }

  .btn-primary {
    padding: 0.625rem 1.5rem;
    background: var(--grad-primary);
    color: var(--on-primary-container);
    border: none;
    font-family: var(--font-ui);
    font-size: var(--body-md);
    cursor: pointer;
    font-weight: 600;
    letter-spacing: 0.02em;
    min-width: 120px;
    box-shadow: var(--glow-primary);
    transition: box-shadow 0.2s;
  }

  .btn-primary:hover {
    box-shadow: var(--glow-primary-strong);
  }

  .error {
    color: var(--red);
    font-size: 0.85rem;
    margin-top: 0.75rem;
  }

  .field {
    display: block;
    text-align: left;
    margin-bottom: 1rem;
  }

  .field-label {
    display: block;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin-bottom: 0.35rem;
  }

  .input {
    width: 100%;
    box-sizing: border-box;
    padding: 0.5rem 0.6rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-primary);
    font: inherit;
    font-size: 0.85rem;
  }

  .input:focus {
    outline: none;
    border-color: var(--primary);
  }

  .fingerprint-card {
    margin-top: 1rem;
    padding: 0.75rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg-primary);
    text-align: left;
  }

  .fingerprint-label {
    display: block;
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin-bottom: 0.35rem;
  }

  .fingerprint-value {
    display: block;
    font-family: var(--font-mono);
    font-size: 0.78rem;
    word-break: break-all;
    color: var(--on-surface);
  }

  .fingerprint-help {
    margin: 0.5rem 0 0;
    font-size: 0.75rem;
    color: var(--text-muted);
    line-height: 1.5;
  }
</style>
