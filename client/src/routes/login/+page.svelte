<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { selfRegistrationEnabled } from "$lib/stores/connection.js";
  import { login, NoPasskeysError } from "$lib/stores/webauthn.js";

  let loading = $state(false);
  let error = $state("");
  let status = $state("");

  async function handleLogin() {
    loading = true;
    error = "";
    status = "Waiting for passkey...";

    try {
      await login();
      window.location.href = "/";
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
    <h1>ShellWatch</h1>
    <p class="subtitle">Touch your passkey to sign in</p>
    <button class="login-btn" disabled={loading} onclick={handleLogin}>
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

  .register-link {
    margin-top: 1.5rem;
    font-size: 0.85rem;
    color: var(--text-muted);
  }

  .register-link a {
    color: var(--accent);
    text-decoration: none;
  }

  .register-link a:hover {
    text-decoration: underline;
  }
</style>
