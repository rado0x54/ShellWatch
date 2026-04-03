<script lang="ts">
  import { get } from "svelte/store";
  import { basePath } from "$lib/stores/connection.js";
  import {
    finishPasskeyRegistration,
    login,
    startPasskeyRegistration,
  } from "$lib/stores/webauthn.js";

  let loading = $state(false);
  let error = $state("");
  let status = $state("");
  let registrationStep = $state<null | {
    challengeId: string;
    credential: unknown;
    suggestedLabel: string;
  }>(null);
  let labelInput = $state("");

  async function handleRegister() {
    loading = true;
    error = "";
    status = "Waiting for passkey...";

    try {
      const result = await startPasskeyRegistration();
      registrationStep = result;
      labelInput = result.suggestedLabel;
      status = "";
      loading = false;
    } catch (err) {
      error = (err as Error).message;
      status = "";
      loading = false;
    }
  }

  async function handleFinishRegistration() {
    if (!registrationStep) return;
    loading = true;
    error = "";
    status = "Completing registration...";

    try {
      await finishPasskeyRegistration(
        registrationStep.challengeId,
        registrationStep.credential as Parameters<typeof finishPasskeyRegistration>[1],
        labelInput || registrationStep.suggestedLabel,
      );
      // Registration complete — log in with the new passkey
      status = "Signing in...";
      await login();
      const base = get(basePath);
      window.location.href = `${base}/`;
    } catch (err) {
      error = (err as Error).message;
      status = "";
      loading = false;
    }
  }
</script>

<div class="onboarding-page">
  <div class="onboarding-card">
    <h1>Welcome to ShellWatch</h1>

    {#if registrationStep}
      <p class="subtitle">Name your passkey</p>
      <input
        type="text"
        class="label-input"
        bind:value={labelInput}
        placeholder="e.g. MacBook Touch ID"
      />
      <button class="btn-primary" disabled={loading} onclick={handleFinishRegistration}>
        Save & Sign In
      </button>
    {:else}
      <p class="subtitle">
        ShellWatch uses passkeys for authentication. No passwords, no emails. Register a passkey to
        get started.
      </p>
      <button class="btn-primary" disabled={loading} onclick={handleRegister}>
        Register Passkey
      </button>
    {/if}

    {#if error}
      <p class="error">{error}</p>
    {/if}
    {#if status}
      <p class="status">{status}</p>
    {/if}
  </div>
</div>

<style>
  .onboarding-page {
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-primary);
  }

  .onboarding-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2.5rem;
    text-align: center;
    max-width: 420px;
    width: 90%;
  }

  h1 {
    font-size: 1.5rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
  }

  .subtitle {
    color: var(--text-muted);
    font-size: 0.9rem;
    margin-bottom: 2rem;
    line-height: 1.5;
  }

  .label-input {
    width: 100%;
    padding: 0.625rem;
    margin-bottom: 1rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 0.9rem;
    text-align: center;
  }

  .btn-primary {
    display: inline-block;
    padding: 0.75rem 2rem;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 6px;
    font-size: 1rem;
    cursor: pointer;
    font-weight: 500;
    width: 100%;
  }

  .btn-primary:hover {
    background: var(--accent-hover);
  }

  .btn-primary:disabled {
    background: #3a3a5a;
    color: #666;
    cursor: default;
  }

  .error {
    color: var(--red);
    font-size: 0.85rem;
    margin-top: 1rem;
  }

  .status {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-top: 1rem;
  }
</style>
