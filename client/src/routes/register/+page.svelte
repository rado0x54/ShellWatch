<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { get } from "svelte/store";
  import { selfRegistrationEnabled } from "$lib/stores/connection.js";
  import { createEndpoint, endpoints, fetchEndpoints } from "$lib/stores/endpoints.js";
  import { formatEndpointAddress, parseEndpointAddress } from "$lib/utils/endpoint-address.js";
  import { generateApiKey } from "$lib/stores/keys.js";
  import { registerAccount } from "$lib/stores/webauthn.js";
  import Wordmark from "$lib/components/Wordmark.svelte";

  let isAdminSetup = $state(false);
  let loading = $state(false);
  let error = $state("");
  let status = $state("");
  let currentStep = $state(0);
  let accountName = $state("");

  // Detect mode on mount: try login/options — if no_passkeys, this is admin setup
  onMount(async () => {
    try {
      const res = await fetch("/api/webauthn/login/options", { method: "POST" });
      const data = await res.json();
      if (data.error === "no_passkeys") {
        isAdminSetup = true;
        accountName = "admin";
      } else {
        // System is bootstrapped — check if self-registration is allowed
        if (!get(selfRegistrationEnabled)) {
          await goto(resolve("/login"));
          return;
        }
      }
    } catch {
      isAdminSetup = true;
      accountName = "admin";
    }
  });

  const steps = ["Welcome", "Passkey", "Endpoints", "MCP"] as const;

  // --- Passkey step ---
  async function handleRegisterPasskey() {
    loading = true;
    error = "";
    status = "Waiting for passkey...";
    try {
      await registerAccount(accountName.trim());
      status = "";
      currentStep = 2;
      await fetchEndpoints();
    } catch (err) {
      error = (err as Error).message;
      status = "";
    }
    loading = false;
  }

  // --- Endpoints step (admin only) ---
  let epLabel = $state("");
  let epAddress = $state("");

  async function handleAddEndpoint() {
    if (!epLabel || !epAddress) {
      error = "Label and Address are required";
      return;
    }
    let parsed;
    try {
      parsed = parseEndpointAddress(epAddress);
    } catch (err) {
      error = (err as Error).message;
      return;
    }
    loading = true;
    error = "";
    try {
      await createEndpoint({
        label: epLabel,
        host: parsed.host,
        port: parsed.port,
        username: parsed.username,
      });
      epLabel = "";
      epAddress = "";
    } catch (err) {
      error = (err as Error).message;
    }
    loading = false;
  }

  // --- MCP step (admin only) ---
  let apiKeyLabel = $state("");
  let generatedKey = $state("");

  const mcpUrl = $derived(`${window.location.origin}/mcp`);

  async function handleGenerateApiKey() {
    if (!apiKeyLabel) {
      error = "Label is required";
      return;
    }
    loading = true;
    error = "";
    try {
      generatedKey = await generateApiKey(apiKeyLabel, ["mcp"]);
      apiKeyLabel = "";
    } catch (err) {
      error = (err as Error).message;
    }
    loading = false;
  }

  function finish() {
    window.location.href = "/";
  }
</script>

<div class="register-page">
  <div class="register-card">
    <!-- Step indicator -->
    <div class="steps">
      {#each steps as step, i (step)}
        <div class="step" class:active={i === currentStep} class:done={i < currentStep}>
          <span class="step-num">{i + 1}</span>
          <span class="step-label">{step}</span>
        </div>
      {/each}
    </div>

    <!-- Step 1: Welcome -->
    {#if currentStep === 0}
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
        <input type="text" class="input" bind:value={accountName} placeholder="Account name" />
      {/if}
      <button
        class="btn-primary"
        disabled={!isAdminSetup && accountName.trim().length < 3}
        onclick={() => (currentStep = 1)}
      >
        Get Started
      </button>

      <!-- Step 2: Passkey -->
    {:else if currentStep === 1}
      <h1>Register a Passkey</h1>
      <p class="description">
        This will be your primary authentication method. You can add more passkeys later in
        settings.
      </p>
      <button class="btn-primary" disabled={loading} onclick={handleRegisterPasskey}>
        Register Passkey
      </button>

      <!-- Step 3: Endpoints (admin only) -->
    {:else if currentStep === 2}
      <h1>Add SSH Endpoints</h1>
      <p class="description">
        Configure the remote servers you want to manage. You can always add more later.
      </p>

      {#if $endpoints.length > 0}
        <div class="endpoint-list">
          {#each $endpoints as ep (ep.id)}
            <div class="endpoint-item">
              <span class="endpoint-label">{ep.label}</span>
              <span class="endpoint-detail">{formatEndpointAddress(ep)}</span>
            </div>
          {/each}
        </div>
      {/if}

      <div class="form-row">
        <input type="text" class="input" bind:value={epLabel} placeholder="Label" />
        <input type="text" class="input" bind:value={epAddress} placeholder="user@host:port" />
      </div>
      <div class="btn-row">
        <button class="btn-secondary" disabled={loading} onclick={handleAddEndpoint}>
          Add Endpoint
        </button>
        <button class="btn-primary" onclick={() => (currentStep = 3)}>
          {$endpoints.length > 0 ? "Continue" : "Skip"}
        </button>
      </div>

      <!-- Step 4: MCP (admin only) -->
    {:else if currentStep === 3}
      <h1>MCP for Agents</h1>
      <p class="description">
        AI agents connect to <Wordmark /> via the Model Context Protocol. Give each agent its own API
        key.
      </p>

      <div class="mcp-url">
        <span class="mcp-label">MCP Endpoint</span>
        <code>{mcpUrl}</code>
      </div>

      {#if generatedKey}
        <div class="generated-key">
          <span class="mcp-label">API Key (copy now — shown only once)</span>
          <code>{generatedKey}</code>
        </div>
      {/if}

      <div class="form-row">
        <input type="text" class="input" bind:value={apiKeyLabel} placeholder="Agent name" />
        <button class="btn-secondary" disabled={loading} onclick={handleGenerateApiKey}>
          Generate Key
        </button>
      </div>

      <button class="btn-primary" onclick={finish}>
        {generatedKey ? "Done" : "Skip"}
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
  .register-page {
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-primary);
  }

  .register-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2.5rem;
    text-align: center;
    max-width: 480px;
    width: 90%;
  }

  .steps {
    display: flex;
    justify-content: center;
    gap: 1.5rem;
    margin-bottom: 2rem;
  }

  .step {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.25rem;
    opacity: 0.35;
  }

  .step.active {
    opacity: 1;
  }

  .step.done {
    opacity: 0.6;
  }

  .step-num {
    width: 1.75rem;
    height: 1.75rem;
    border-radius: 50%;
    background: var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.75rem;
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
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
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
    margin-bottom: 1rem;
  }

  h1 {
    font-size: 1.35rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
  }

  .description,
  .hint {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-bottom: 1rem;
    line-height: 1.6;
  }

  .input {
    margin-bottom: 1rem;
  }

  .form-row {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  .form-row .input {
    flex: 1;
    min-width: 0;
    margin-bottom: 0;
  }

  .btn-row {
    display: flex;
    gap: 0.5rem;
    justify-content: center;
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
    padding: 0.625rem 1.5rem;
    background: var(--bg-primary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.9rem;
    cursor: pointer;
  }

  .btn-secondary:hover {
    background: var(--border);
  }

  .btn-secondary:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .endpoint-list {
    margin-bottom: 1rem;
    text-align: left;
  }

  .endpoint-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 0.75rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 0.375rem;
  }

  .endpoint-label {
    font-weight: 600;
    font-size: 0.8rem;
  }

  .endpoint-detail {
    font-size: 0.75rem;
    color: var(--text-muted);
  }

  .mcp-url,
  .generated-key {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.75rem;
    margin-bottom: 1rem;
    text-align: left;
  }

  .mcp-label {
    display: block;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin-bottom: 0.375rem;
  }

  code {
    font-size: 0.8rem;
    word-break: break-all;
  }

  .generated-key code {
    color: var(--green, #4ade80);
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
