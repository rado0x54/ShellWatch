<script lang="ts">
  import { get } from "svelte/store";
  import { basePath } from "$lib/stores/connection.js";
  import { createEndpoint, endpoints, fetchEndpoints } from "$lib/stores/endpoints.js";
  import { generateApiKey } from "$lib/stores/keys.js";
  import {
    finishPasskeyRegistration,
    login,
    startPasskeyRegistration,
  } from "$lib/stores/webauthn.js";

  const steps = ["Welcome", "Passkey", "Endpoints", "MCP"] as const;
  let currentStep = $state(0);
  let loading = $state(false);
  let error = $state("");
  let status = $state("");

  // --- Step 2: Passkey ---
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
    status = "Completing registration...";
    try {
      await finishPasskeyRegistration(
        registrationStep.challengeId,
        registrationStep.credential as Parameters<typeof finishPasskeyRegistration>[1],
        labelInput || registrationStep.suggestedLabel,
      );
      status = "Signing in...";
      await login();
      registrationStep = null;
      currentStep = 2;
      status = "";
      await fetchEndpoints();
    } catch (err) {
      error = (err as Error).message;
      status = "";
    }
    loading = false;
  }

  // --- Step 3: Endpoints ---
  let epHost = $state("");
  let epPort = $state(22);
  let epUsername = $state("");
  let epLabel = $state("");

  const epId = $derived(
    epLabel
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, ""),
  );

  async function handleAddEndpoint() {
    if (!epLabel || !epHost || !epUsername) {
      error = "Label, Host, and Username are required";
      return;
    }
    loading = true;
    error = "";
    try {
      await createEndpoint({
        id: epId,
        label: epLabel,
        host: epHost,
        port: epPort,
        username: epUsername,
      });
      epHost = "";
      epPort = 22;
      epUsername = "";
      epLabel = "";
    } catch (err) {
      error = (err as Error).message;
    }
    loading = false;
  }

  // --- Step 4: MCP ---
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

<div class="onboarding-page">
  <div class="onboarding-card">
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
      <p class="description">
        ShellWatch is an SSH session broker that lets you and your AI agents securely manage remote
        servers through a unified interface.
      </p>
      <p class="description">
        Authentication is passkey-only. No passwords, no emails. Your passkey is the only way to
        access this instance.
      </p>
      <button class="btn-primary" onclick={() => (currentStep = 1)}>Get Started</button>

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
          Save & Sign In
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

      <!-- Step 3: Endpoints -->
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
              <span class="endpoint-detail">{ep.username}@{ep.host}:{ep.port}</span>
            </div>
          {/each}
        </div>
      {/if}

      <div class="form-grid">
        <input type="text" class="input" bind:value={epLabel} placeholder="Label" />
        <input type="text" class="input" bind:value={epHost} placeholder="Host" />
        <input type="number" class="input input-sm" bind:value={epPort} placeholder="Port" />
        <input type="text" class="input" bind:value={epUsername} placeholder="Username" />
      </div>
      <div class="btn-row">
        <button class="btn-secondary" disabled={loading} onclick={handleAddEndpoint}>
          Add Endpoint
        </button>
        <button class="btn-primary" onclick={() => (currentStep = 3)}>
          {$endpoints.length > 0 ? "Continue" : "Skip"}
        </button>
      </div>

      <!-- Step 4: MCP -->
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
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 0.85rem;
  }

  .input-sm {
    max-width: 80px;
  }

  .form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  .form-row {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
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
