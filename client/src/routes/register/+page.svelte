<script lang="ts">
  import { onMount } from "svelte";
  import { get } from "svelte/store";
  import { basePath } from "$lib/stores/connection.js";
  import { createEndpoint, endpoints, fetchEndpoints } from "$lib/stores/endpoints.js";
  import { formatEndpointAddress, parseEndpointAddress } from "$lib/utils/endpoint-address.js";
  import { generateApiKey } from "$lib/stores/keys.js";
  import { registerAccount, startPasskeyRegistration } from "$lib/stores/webauthn.js";

  let isAdminSetup = $state(false);
  let loading = $state(false);
  let error = $state("");
  let status = $state("");
  let currentStep = $state(0);

  // Detect mode on mount: try login/options — if no_passkeys, this is admin setup
  onMount(async () => {
    const base = get(basePath);
    try {
      const res = await fetch(`${base}/api/webauthn/login/options`, { method: "POST" });
      const data = await res.json();
      if (data.error === "no_passkeys") {
        isAdminSetup = true;
      }
    } catch {
      // Network error — assume admin setup
      isAdminSetup = true;
    }
  });

  const steps = $derived(
    isAdminSetup
      ? (["Welcome", "Passkey", "Endpoints", "MCP"] as const)
      : (["Welcome", "Passkey"] as const),
  );

  // --- Passkey step ---
  let accountName = $state("");
  let registrationStep = $state<null | {
    challengeId: string;
    credential: unknown;
    suggestedLabel: string;
  }>(null);
  let labelInput = $state("");

  async function handleRegisterPasskey() {
    loading = true;
    error = "";
    status = "Waiting for passkey...";
    try {
      const result = await startPasskeyRegistration();
      registrationStep = result;
      labelInput = result.suggestedLabel;
      status = "";
    } catch (err) {
      error = (err as Error).message;
      status = "";
    }
    loading = false;
  }

  async function handleFinishPasskey() {
    if (!registrationStep) return;
    loading = true;
    error = "";
    status = "Creating account...";
    try {
      await registerAccount(
        accountName || "User",
        registrationStep.challengeId,
        registrationStep.credential as Parameters<typeof registerAccount>[2],
        labelInput || registrationStep.suggestedLabel,
      );
      registrationStep = null;
      status = "";

      if (isAdminSetup) {
        currentStep = 2;
        await fetchEndpoints();
      } else {
        // User registration complete — go to app
        const base = get(basePath);
        window.location.href = `${base}/`;
      }
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

  const mcpUrl = $derived(`${window.location.origin}${get(basePath)}/mcp`);

  async function handleGenerateApiKey() {
    if (!apiKeyLabel) {
      error = "Label is required";
      return;
    }
    loading = true;
    error = "";
    try {
      generatedKey = await generateApiKey(apiKeyLabel);
      apiKeyLabel = "";
    } catch (err) {
      error = (err as Error).message;
    }
    loading = false;
  }

  function finish() {
    const base = get(basePath);
    window.location.href = `${base}/`;
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
      <h1>Welcome to ShellWatch</h1>
      {#if isAdminSetup}
        <div class="admin-badge">Admin Setup</div>
        <p class="description">
          You are the first user — your account will be the administrator. This gives you access to
          file-based SSH keys and account management.
        </p>
      {:else}
        <p class="description">
          Create your account to get started. Authentication is passkey-only — no passwords, no
          emails.
        </p>
      {/if}
      <p class="description">
        ShellWatch is an SSH session broker that lets you and your AI agents securely manage remote
        servers through a unified interface.
      </p>
      <input type="text" class="input" bind:value={accountName} placeholder="Your name" />
      <button class="btn-primary" disabled={!accountName} onclick={() => (currentStep = 1)}>
        Continue
      </button>

      <!-- Step 2: Passkey -->
    {:else if currentStep === 1}
      <h1>Register a Passkey</h1>
      {#if registrationStep}
        <p class="description">Name your passkey so you can identify it later.</p>
        <input
          type="text"
          class="input"
          bind:value={labelInput}
          placeholder="e.g. MacBook Touch ID"
        />
        <button class="btn-primary" disabled={loading} onclick={handleFinishPasskey}>
          {isAdminSetup ? "Save & Continue" : "Save & Sign In"}
        </button>
      {:else}
        <p class="description">
          This will be your primary authentication method. You can add more passkeys later in
          settings.
        </p>
        <button class="btn-primary" disabled={loading} onclick={handleRegisterPasskey}>
          Register Passkey
        </button>
      {/if}

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
        AI agents connect to ShellWatch via the Model Context Protocol. Give each agent its own API
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

  .description {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-bottom: 1rem;
    line-height: 1.6;
  }

  .input {
    width: 100%;
    padding: 0.625rem;
    margin-bottom: 1rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 0.85rem;
  }

  .form-row {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  .form-row .input {
    margin-bottom: 0;
  }

  .btn-row {
    display: flex;
    gap: 0.5rem;
    justify-content: center;
  }

  .btn-primary {
    padding: 0.625rem 1.5rem;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 6px;
    font-size: 0.9rem;
    cursor: pointer;
    font-weight: 500;
    min-width: 120px;
  }

  .btn-primary:hover {
    background: var(--accent-hover);
  }

  .btn-primary:disabled {
    background: #3a3a5a;
    color: #666;
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
