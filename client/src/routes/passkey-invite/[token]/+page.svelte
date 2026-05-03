<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import { page } from "$app/state";
  import { fetchInviteByToken, registerWithInviteToken } from "$lib/stores/webauthn.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import Wordmark from "$lib/components/Wordmark.svelte";

  // ready       — slot is alive; user clicks Register to run the WebAuthn ceremony
  // registering — ceremony + insert in flight
  // done        — credential created; user reads the fingerprint, then leaves.
  //               Renaming is intentionally device A's job (any rename done by
  //               an intercepted token would weaponise device A's confirm UI).
  // unavailable / error — terminal failure states
  type LocalState = "loading" | "ready" | "registering" | "done" | "unavailable" | "error";

  let local = $state<LocalState>("loading");
  let accountName = $state<string | null>(null);
  let assignedLabel = $state("");
  let assignedFingerprint = $state<string | null>(null);
  let expiresAt = $state("");
  let error = $state("");
  // Ticks every second while the slot is still relevant — drives the live m:ss
  // countdown and flips to "unavailable" if the user just sat on the page.
  let now = $state(Date.now());

  const token = $derived(page.params.token ?? "");

  $effect(() => {
    if (local !== "ready") return;
    const id = setInterval(() => {
      now = Date.now();
    }, 1000);
    return () => clearInterval(id);
  });

  const remainingMs = $derived(expiresAt ? Date.parse(expiresAt) - now : 0);

  $effect(() => {
    if (local === "ready" && remainingMs <= 0) {
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
      local = "done";
    } catch (err) {
      error = errorMessage(err);
      local = "ready";
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
      <button type="button" class="btn-primary" onclick={handleRegister}>Register passkey</button>
      {#if error}
        <p class="error">{error}</p>
      {/if}
    {:else if local === "registering"}
      <p class="status">Waiting for your authenticator…</p>
    {:else if local === "done"}
      <p class="description">
        <span class="check">✓</span> Passkey registered as <strong>{assignedLabel}</strong>. Now go
        back to the original device and click <strong>Confirm</strong> there to activate it. The passkey
        can't be used until that confirmation lands.
      </p>
      {#if assignedFingerprint}
        <div class="fingerprint-card">
          <span class="fingerprint-label">Fingerprint</span>
          <code class="fingerprint-value">{assignedFingerprint}</code>
          <p class="fingerprint-help">
            Verify this exact string is also shown on the original device's confirmation dialog
            before activating.
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
