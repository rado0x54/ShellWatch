<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { apiFetch } from "$lib/api.js";
  import { onMount } from "svelte";
  import { get } from "svelte/store";
  import { selfRegistrationEnabled } from "$lib/stores/connection.js";
  import { registerAccount } from "$lib/stores/webauthn.js";
  import { beginLogin } from "$lib/oauth.js";
  import Wordmark from "$lib/components/Wordmark.svelte";

  // Onboarding is a minimum-friction path: name → register a passkey → sign in.
  // Registration creates the account + passkey but issues no token (the web UI
  // is a browser OAuth client, #217); the final step starts the PKCE login flow,
  // where the just-created passkey authenticates you into the app. Notification
  // setup lives in Settings → Notifications (it needs an authenticated session).
  type StepId = "welcome" | "passkey";

  const stepOrder: { id: StepId; label: string }[] = [
    { id: "welcome", label: "Welcome" },
    { id: "passkey", label: "Passkey" },
  ];

  let isAdminSetup = $state(false);
  let loading = $state(false);
  let error = $state("");
  let status = $state("");
  let stepIdx = $state(0);
  let accountName = $state("");
  let registeredCredentialId = $state<string | null>(null);
  let registeredLabel = $state<string | null>(null);

  const currentStep = $derived(stepOrder[stepIdx].id);
  const currentLabel = $derived(stepOrder[stepIdx].label);

  function next() {
    error = "";
    if (stepIdx < stepOrder.length - 1) stepIdx += 1;
  }

  function back() {
    error = "";
    if (stepIdx > 0) stepIdx -= 1;
  }

  // Detect mode on mount
  onMount(async () => {
    try {
      const res = await apiFetch("/api/auth/passkey-status");
      const data = await res.json();
      if (!data.hasPasskeys) {
        // First-run admin bootstrap — no passkeys exist yet.
        isAdminSetup = true;
        accountName = "admin";
      } else {
        if (!get(selfRegistrationEnabled)) {
          // Registration closed and an admin already exists — bounce back into
          // the sign-in flow (Hydra owns the login UI).
          await beginLogin("/");
          return;
        }
      }
    } catch {
      isAdminSetup = true;
      accountName = "admin";
    }
  });

  // --- Passkey step ---
  // Register only creates the account + passkey; it sets no session. We use the
  // label returned directly (no authenticated /api/webauthn/credentials read —
  // that would 401 and bounce us out of the wizard).
  async function handleRegisterPasskey() {
    loading = true;
    error = "";
    status = "Waiting for passkey...";
    try {
      const result = await registerAccount(accountName.trim());
      registeredCredentialId = result.credentialId;
      registeredLabel = result.label;
      status = "";
    } catch (err) {
      error = (err as Error).message;
      status = "";
    }
    loading = false;
  }

  // Final step: start the OAuth PKCE login (full-page redirect to Hydra → the
  // passkey just registered authenticates you → back into the app).
  async function signIn() {
    loading = true;
    error = "";
    status = "Redirecting to sign-in…";
    try {
      await beginLogin("/");
    } catch (err) {
      error = (err as Error).message;
      status = "";
      loading = false;
    }
  }
</script>

<div class="register-page">
  <div class="register-card">
    <!-- Step indicator: numbered dots, labels hidden on mobile -->
    <div class="steps" aria-label={`Step ${stepIdx + 1} of ${stepOrder.length}: ${currentLabel}`}>
      {#each stepOrder as step, i (step.id)}
        <div
          class="step"
          class:active={i === stepIdx}
          class:done={i < stepIdx}
          aria-current={i === stepIdx ? "step" : undefined}
        >
          <span class="step-num">{i + 1}</span>
          <span class="step-label">{step.label}</span>
        </div>
      {/each}
    </div>
    <p class="step-headline">
      Step {stepIdx + 1} of {stepOrder.length} · {currentLabel}
    </p>

    {#if currentStep === "welcome"}
      <h1>Welcome to <Wordmark /></h1>
      {#if isAdminSetup}
        <div class="admin-badge">Admin Setup</div>
        <p class="description">
          You are the first user — your account will be the administrator. This gives you access to
          file-based SSH keys and account management.
        </p>
      {/if}
      <p class="description">
        <Wordmark /> is an SSH session broker that lets you and your AI agents securely manage remote
        servers through a unified interface. Authentication is passkey-only — no passwords, no emails.
      </p>
      {#if !isAdminSetup}
        <p class="hint">
          Choose a name for your account (3+ characters). This does not need to contain personal
          information — it is written into your passkey to help identify the account. You can change
          it later in Settings (existing passkeys are not updated).
        </p>
        <input
          type="text"
          class="input"
          bind:value={accountName}
          placeholder="Account name"
          disabled={!!registeredCredentialId}
        />
        {#if registeredCredentialId}
          <p class="hint">
            <span class="check">✓</span> Account already created — name is locked. Change it later in
            Settings.
          </p>
        {/if}
      {/if}
      <button
        type="button"
        class="btn-primary"
        disabled={!isAdminSetup && !registeredCredentialId && accountName.trim().length < 3}
        onclick={next}
      >
        Get Started
      </button>
    {:else if currentStep === "passkey"}
      <h1>Register a Passkey</h1>
      {#if registeredCredentialId}
        <p class="description">
          <span class="check">✓</span> Passkey registered{registeredLabel
            ? ` as ${registeredLabel}`
            : ""}. One more step — sign in with it to enter ShellWatch. You can manage passkeys and
          notifications in Settings.
        </p>
        <div class="nav-row">
          <button type="button" class="btn-primary" disabled={loading} onclick={signIn}>
            Sign in
          </button>
        </div>
      {:else}
        <p class="description">
          This will be your primary authentication method. You can add more passkeys later in
          settings.
        </p>
        <div class="nav-row">
          <button type="button" class="btn-secondary" onclick={back}>Back</button>
          <button
            type="button"
            class="btn-primary"
            disabled={loading}
            onclick={handleRegisterPasskey}
          >
            Register Passkey
          </button>
        </div>
      {/if}
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
  .register-page {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-primary);
    padding: 1rem;
    box-sizing: border-box;
  }

  .register-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem;
    text-align: center;
    max-width: 480px;
    width: 100%;
    box-sizing: border-box;
  }

  .steps {
    display: flex;
    justify-content: center;
    gap: 0.75rem;
    margin-bottom: 0.5rem;
  }

  .step {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.25rem;
    opacity: 0.35;
    flex: 0 0 auto;
  }

  .step.active {
    opacity: 1;
  }

  .step.done {
    opacity: 0.6;
  }

  .step-num {
    width: 1.5rem;
    height: 1.5rem;
    border-radius: 50%;
    background: var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.7rem;
    font-weight: 600;
  }

  .step.active .step-num {
    background: var(--accent);
    color: #fff;
  }

  .step.done .step-num {
    background: var(--green, #4ade80);
    color: #fff;
  }

  .step-label {
    font-size: 0.6rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
  }

  .step-headline {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 1rem;
  }

  .admin-badge {
    display: inline-block;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 4px;
    padding: 0.2rem 0.5rem;
    margin-bottom: 0.75rem;
  }

  h1 {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
  }

  .description,
  .hint {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-bottom: 0.75rem;
    line-height: 1.55;
  }

  .hint {
    font-size: 0.78rem;
  }

  .input {
    margin-bottom: 0.75rem;
  }

  /* Footer nav row: Back on the left, Continue / primary on the right. */
  .nav-row {
    display: flex;
    gap: 0.5rem;
    justify-content: space-between;
    align-items: center;
    margin-top: 0.25rem;
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

  .btn-primary:disabled {
    background: var(--surface-container-high);
    color: var(--on-surface-faint);
    box-shadow: none;
    cursor: default;
  }

  .btn-secondary {
    padding: 0.625rem 1.25rem;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .btn-secondary:hover {
    background: var(--border);
  }

  .btn-secondary:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .error {
    color: var(--red);
    font-size: 0.85rem;
    margin-top: 0.75rem;
  }

  .status {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-top: 0.75rem;
  }

  /* Mobile: tighten card, hide step labels (keep numbers + headline). */
  @media (max-width: 640px) {
    .register-page {
      padding: 0.5rem;
      align-items: flex-start;
    }

    .register-card {
      padding: 1.25rem 1rem;
    }

    .steps {
      gap: 0.5rem;
    }

    .step-label {
      display: none;
    }

    h1 {
      font-size: 1.1rem;
    }

    .description {
      font-size: 0.82rem;
    }

    .hint {
      font-size: 0.76rem;
    }
  }
</style>
