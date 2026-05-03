<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/state";
  import Wordmark from "$lib/components/Wordmark.svelte";
  import { selfRegistrationEnabled } from "$lib/stores/connection.js";
  import { login, NoPasskeysError } from "$lib/stores/webauthn.js";

  let loading = $state(false);
  let error = $state("");
  let status = $state("");

  function safeRedirect(): string {
    const raw = page.url.searchParams.get("redirect");
    if (!raw) return "/";
    // Only accept same-origin paths: must start with `/` followed by a character
    // that is neither `/` nor `\` (some browsers normalize `\` to `/`, which
    // would otherwise let `/\evil.com` escape to an attacker host).
    if (!/^\/[^/\\]/.test(raw)) return "/";
    return raw;
  }

  async function handleLogin() {
    loading = true;
    error = "";
    status = "Waiting for passkey...";

    try {
      await login();
      window.location.href = safeRedirect();
    } catch (err) {
      if (err instanceof NoPasskeysError) {
        await goto(resolve("/register"));
        return;
      }
      error = (err as Error).message;
      status = "";
      loading = false;
    }
  }
</script>

<div class="login-page">
  <div class="login-card">
    <img class="login-logo" src="/logo.svg" alt="" />
    <h1 class="wordmark-h1"><Wordmark /></h1>
    <button type="button" class="login-btn" disabled={loading} onclick={handleLogin}>
      Sign in with Passkey
    </button>
    {#if error}
      <p class="error">{error}</p>
    {/if}
    {#if status}
      <p class="status">{status}</p>
    {/if}
    {#if $selfRegistrationEnabled}
      <p class="register-link">
        <a href={resolve("/register")}>Create new account</a>
      </p>
    {/if}
  </div>
</div>

<style>
  .login-page {
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--surface-dim);
  }

  .login-card {
    background: var(--surface-container-low);
    padding: var(--space-7);
    text-align: center;
    max-width: 380px;
    width: 90%;
  }

  .login-logo {
    width: 176px;
    height: 176px;
    display: block;
    margin: 0 auto var(--space-2);
  }

  .wordmark-h1 {
    font-size: 2rem;
    margin-bottom: var(--space-7);
    line-height: 1;
  }

  .login-btn {
    display: inline-block;
    padding: 0.75rem 2rem;
    background: var(--grad-primary);
    color: var(--on-primary-container);
    border: none;
    font-family: var(--font-ui);
    font-size: var(--body-md);
    cursor: pointer;
    font-weight: 600;
    letter-spacing: 0.02em;
    width: 100%;
    box-shadow: var(--glow-primary);
    transition: box-shadow 0.2s;
  }

  .login-btn:hover {
    box-shadow: var(--glow-primary-strong);
  }

  .login-btn:disabled {
    background: var(--surface-container-high);
    color: var(--on-surface-faint);
    box-shadow: none;
    cursor: default;
  }

  .error {
    color: var(--error);
    font-size: var(--body-md);
    margin-top: var(--space-4);
  }

  .status {
    font-family: var(--font-mono);
    color: var(--on-surface-variant);
    font-size: var(--label-sm);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    margin-top: var(--space-4);
  }

  .register-link {
    margin-top: var(--space-5);
    font-size: var(--body-md);
    color: var(--on-surface-variant);
  }

  .register-link a {
    color: var(--primary);
    text-decoration: none;
  }

  .register-link a:hover {
    text-decoration: underline;
  }
</style>
