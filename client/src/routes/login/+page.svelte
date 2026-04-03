<script lang="ts">
  import { get } from "svelte/store";
  import { basePath } from "$lib/stores/connection.js";
  import {
    finishPasskeyRegistration,
    login,
    NoPasskeysError,
    startPasskeyRegistration,
  } from "$lib/stores/webauthn.js";

  let loading = $state(false);
  let error = $state("");
  let status = $state("");
  let needsRegistration = $state(false);
  let registrationStep = $state<null | {
    challengeId: string;
    credential: unknown;
    suggestedLabel: string;
  }>(null);
  let labelInput = $state("");

  async function handleLogin() {
    loading = true;
    error = "";
    status = "Waiting for passkey...";

    try {
      await login();
      const base = get(basePath);
      window.location.href = `${base}/`;
    } catch (err) {
      if (err instanceof NoPasskeysError) {
        needsRegistration = true;
        status = "";
      } else {
        error = (err as Error).message;
        status = "";
      }
      loading = false;
    }
  }

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

    try {
      await finishPasskeyRegistration(
        registrationStep.challengeId,
        registrationStep.credential as Parameters<typeof finishPasskeyRegistration>[1],
        labelInput || registrationStep.suggestedLabel,
      );
      // Registration complete — now login
      registrationStep = null;
      needsRegistration = false;
      await handleLogin();
    } catch (err) {
      error = (err as Error).message;
      loading = false;
    }
  }
</script>

<div class="login-page">
  <div class="login-card">
    <h1>ShellWatch</h1>

    {#if registrationStep}
      <p class="subtitle">Name your passkey</p>
      <input
        type="text"
        class="label-input"
        bind:value={labelInput}
        placeholder="e.g. MacBook Touch ID"
      />
      <button class="login-btn" disabled={loading} onclick={handleFinishRegistration}>
        Save & Sign In
      </button>
    {:else if needsRegistration}
      <p class="subtitle">No passkeys registered. Register one to get started.</p>
      <button class="login-btn" disabled={loading} onclick={handleRegister}>
        Register Passkey
      </button>
    {:else}
      <p class="subtitle">Touch your passkey to sign in</p>
      <button class="login-btn" disabled={loading} onclick={handleLogin}>
        Sign in with Passkey
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
  .login-page {
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-primary);
  }

  .login-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2.5rem;
    text-align: center;
    max-width: 380px;
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

  .login-btn {
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

  .login-btn:hover {
    background: var(--accent-hover);
  }

  .login-btn:disabled {
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
