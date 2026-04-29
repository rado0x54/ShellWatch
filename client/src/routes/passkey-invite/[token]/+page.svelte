<script lang="ts">
  import { onMount } from "svelte";
  import { page } from "$app/state";
  import {
    confirmInviteLabel,
    fetchInviteByToken,
    registerWithInviteToken,
  } from "$lib/stores/webauthn.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import Wordmark from "$lib/components/Wordmark.svelte";

  // ready    — slot is alive; user clicks Register to run the WebAuthn ceremony
  // registering — ceremony in flight
  // naming   — server returned an AAGUID-derived label; user confirms or edits
  // saving   — PATCH in flight (rename PATCH)
  // done     — slot consumed; rename window closed; user can leave
  // unavailable / error — terminal failure states
  type LocalState =
    | "loading"
    | "ready"
    | "registering"
    | "naming"
    | "saving"
    | "done"
    | "unavailable"
    | "error";

  let local = $state<LocalState>("loading");
  let accountName = $state<string | null>(null);
  let labelInput = $state("");
  let assignedLabel = $state("");
  let assignedFingerprint = $state<string | null>(null);
  let expiresAt = $state("");
  let error = $state("");
  // Ticks every second while the page is in the "ready" state — drives the
  // live m:ss countdown and flips to "unavailable" the instant the slot
  // expires (even if the user just sat on the page).
  let now = $state(Date.now());

  const token = $derived(page.params.token ?? "");

  $effect(() => {
    // Run the timer in any state where the slot is still relevant. Once the
    // user is past the rename ("done") or unavailable, the timer is moot.
    if (local !== "ready" && local !== "naming") return;
    const id = setInterval(() => {
      now = Date.now();
    }, 1000);
    return () => clearInterval(id);
  });

  const remainingMs = $derived(expiresAt ? Date.parse(expiresAt) - now : 0);

  $effect(() => {
    if ((local === "ready" || local === "naming") && remainingMs <= 0) {
      local = "unavailable";
    }
  });

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
      accountName = info.accountName;
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
      const result = await registerWithInviteToken({ token });
      assignedLabel = result.label;
      assignedFingerprint = result.fingerprint;
      labelInput = result.label;
      local = "naming";
    } catch (err) {
      error = errorMessage(err);
      local = "ready";
    }
  }

  async function handleConfirmName() {
    if (!token) return;
    const trimmed = labelInput.trim();
    if (!trimmed) {
      error = "Pick a name for this passkey";
      return;
    }
    local = "saving";
    error = "";
    try {
      const result = await confirmInviteLabel({ token, label: trimmed });
      assignedLabel = result.label;
      local = "done";
    } catch (err) {
      error = errorMessage(err);
      local = "naming";
    }
  }

  function formatRemaining(ms: number): string {
    if (ms <= 0) return "0:00";
    const totalSec = Math.ceil(ms / 1000);
    const mins = Math.floor(totalSec / 60);
    const secs = totalSec % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  }
</script>

<div class="invite-page">
  <div class="invite-card">
    <h1>Add a passkey to <Wordmark /></h1>
    {#if accountName}
      <p class="account">for <strong>{accountName}</strong></p>
    {/if}

    {#if local === "loading"}
      <p class="status">Loading invite…</p>
    {:else if local === "ready"}
      <div class="invite-status">
        <span class="invite-status-dot" aria-hidden="true"></span>
        <span class="invite-status-label">Active</span>
        <span class="invite-status-timer">{formatRemaining(remainingMs)}</span>
      </div>
      <p class="description">
        Register a new passkey on this device. The other device will need to confirm it before it's
        usable.
      </p>
      <button class="btn-primary" onclick={handleRegister}>Register passkey</button>
      {#if error}
        <p class="error">{error}</p>
      {/if}
    {:else if local === "registering"}
      <p class="status">Waiting for your authenticator…</p>
    {:else if local === "naming" || local === "saving"}
      <div class="invite-status">
        <span class="invite-status-dot" aria-hidden="true"></span>
        <span class="invite-status-label">Active</span>
        <span class="invite-status-timer">{formatRemaining(remainingMs)}</span>
      </div>
      <p class="description">
        Passkey registered. Pick a name for it — you can keep the suggestion or change it. After you
        confirm, this name is locked.
      </p>
      <label class="field">
        <span class="field-label">Passkey name</span>
        <input
          class="input"
          type="text"
          bind:value={labelInput}
          maxlength="64"
          disabled={local === "saving"}
        />
      </label>
      {#if assignedFingerprint}
        <div class="fingerprint-card">
          <span class="fingerprint-label">Fingerprint</span>
          <code class="fingerprint-value">{assignedFingerprint}</code>
          <p class="fingerprint-help">
            Verify this matches the fingerprint shown on the original device when you confirm there.
          </p>
        </div>
      {/if}
      <button class="btn-primary" onclick={handleConfirmName} disabled={local === "saving"}>
        {local === "saving" ? "Saving…" : "Confirm name"}
      </button>
      {#if error}
        <p class="error">{error}</p>
      {/if}
    {:else if local === "done"}
      <p class="description">
        <span class="check">✓</span> Passkey <strong>{assignedLabel}</strong> registered. Go back to
        the original device and click <strong>Confirm</strong> to activate it. Until then, this passkey
        can't be used.
      </p>
      {#if assignedFingerprint}
        <div class="fingerprint-card">
          <span class="fingerprint-label">Fingerprint</span>
          <code class="fingerprint-value">{assignedFingerprint}</code>
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

  .account {
    font-size: 0.78rem;
    color: var(--text-muted);
    margin: -0.25rem 0 0.75rem;
  }

  /* Same green status pill used in the in-account modal. Standalone line, not
     inline in the body copy. */
  .invite-status {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.3rem 0.7rem;
    margin-bottom: 0.85rem;
    background: color-mix(in srgb, var(--green, #4ade80) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--green, #4ade80) 50%, transparent);
    border-radius: 999px;
  }

  .invite-status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--green, #4ade80);
    box-shadow: 0 0 6px color-mix(in srgb, var(--green, #4ade80) 70%, transparent);
    animation: invite-pulse 1.6s ease-out infinite;
  }

  .invite-status-label {
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--green, #4ade80);
  }

  .invite-status-timer {
    font-family: var(--font-mono);
    font-variant-numeric: tabular-nums;
    font-size: 0.85rem;
    color: var(--green, #4ade80);
    font-weight: 600;
  }

  @keyframes invite-pulse {
    0% {
      box-shadow: 0 0 0 0 var(--green, #4ade80);
      opacity: 1;
    }
    70% {
      box-shadow: 0 0 0 6px transparent;
      opacity: 0.6;
    }
    100% {
      box-shadow: 0 0 0 0 transparent;
      opacity: 1;
    }
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
