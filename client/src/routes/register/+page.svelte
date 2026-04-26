<script lang="ts">
  import { onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { get } from "svelte/store";
  import { selfRegistrationEnabled } from "$lib/stores/connection.js";
  import { createEndpoint, endpoints, fetchEndpoints } from "$lib/stores/endpoints.js";
  import { formatEndpointAddress, parseEndpointAddress } from "$lib/utils/endpoint-address.js";
  import { generateApiKey } from "$lib/stores/keys.js";
  import {
    pushEnabled,
    pushLoading,
    pushSupported,
    subscribePush,
    unsubscribePush,
    vapidAvailable,
    checkPushStatus,
  } from "$lib/stores/push.js";
  import { credentials, fetchCredentials, registerAccount } from "$lib/stores/webauthn.js";
  import Wordmark from "$lib/components/Wordmark.svelte";

  type StepId =
    | "welcome"
    | "passkey"
    | "server-setup"
    | "endpoints"
    | "mcp"
    | "notifications"
    | "advanced";

  const stepOrder: { id: StepId; label: string }[] = [
    { id: "welcome", label: "Welcome" },
    { id: "passkey", label: "Passkey" },
    { id: "server-setup", label: "Server" },
    { id: "endpoints", label: "Endpoints" },
    { id: "mcp", label: "MCP" },
    { id: "notifications", label: "Notify" },
    { id: "advanced", label: "Done" },
  ];

  let isAdminSetup = $state(false);
  let loading = $state(false);
  let error = $state("");
  let status = $state("");
  let stepIdx = $state(0);
  let accountName = $state("");
  let registeredCredentialId = $state<string | null>(null);
  let vapidConfigured = $state(false);

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
      const res = await fetch("/api/auth/login/options", { method: "POST" });
      const data = await res.json();
      if (data.error === "no_passkeys") {
        isAdminSetup = true;
        accountName = "admin";
      } else {
        if (!get(selfRegistrationEnabled)) {
          await goto(resolve("/login"));
          return;
        }
      }
    } catch {
      isAdminSetup = true;
      accountName = "admin";
    }
    vapidConfigured = vapidAvailable();
  });

  // --- Passkey step ---
  async function handleRegisterPasskey() {
    loading = true;
    error = "";
    status = "Waiting for passkey...";
    try {
      const result = await registerAccount(accountName.trim());
      registeredCredentialId = result.credentialId;
      status = "";
      // Pull the freshly-stored credential row so we can show its
      // authorized_keys entry on the server-setup step. Also pre-fetch
      // endpoints so admin's seeded entries appear when they reach that step.
      await Promise.all([fetchCredentials(), fetchEndpoints()]);
      next();
    } catch (err) {
      error = (err as Error).message;
      status = "";
    }
    loading = false;
  }

  // --- Server setup step ---
  // registerAccount returns the WebAuthn credentialId (base64url), not the
  // row UUID — so match on credentialId, not the row's `id` field.
  const registeredCred = $derived(
    $credentials.find((c) => c.credentialId === registeredCredentialId) ?? null,
  );

  function sshComment(label: string): string {
    const sanitize = (s: string) =>
      s
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "_")
        .replace(/_+/g, "_")
        .replace(/^_|_$/g, "");
    const host = sanitize(window.location.hostname);
    const name = sanitize(accountName.trim() || "user");
    const key = sanitize(label);
    return `${host}-${name}-${key}`;
  }

  const sshLine = $derived(
    registeredCred?.authorizedKeysEntry
      ? `${registeredCred.authorizedKeysEntry} ${sshComment(registeredCred.label)}`
      : null,
  );

  const sshOneLiner = $derived(sshLine ? `echo '${sshLine}' >> ~/.ssh/authorized_keys` : null);

  // Single source for the sshd line — referenced from both the visible code
  // block and the clipboard handler so they can't drift. Mirrors the value
  // computed server-side in src/webauthn/ssh-key-format.ts; if that changes
  // (additional algorithms, multi-line config), surface it through the
  // register response and consume it here instead.
  const SSHD_CONFIG_LINE = "PubkeyAcceptedAlgorithms=+webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

  async function copyToClipboard(text: string, btn: HTMLButtonElement) {
    const original = btn.innerHTML;
    try {
      await navigator.clipboard.writeText(text);
      btn.innerHTML = "&#10003; Copied";
    } catch {
      // Insecure context (HTTP non-localhost) or denied permission — surface
      // the failure instead of flashing a false-positive "Copied" state.
      btn.innerHTML = "Copy failed";
    }
    setTimeout(() => {
      btn.innerHTML = original;
    }, 1500);
  }

  // --- Endpoints step ---
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

  // --- MCP step ---
  let apiKeyLabel = $state("");
  let generatedKey = $state("");
  let showApiKeyForm = $state(false);

  const mcpUrl = $derived(`${window.location.origin}/mcp`);

  // Sample config for non-OAuth MCP clients (HTTP-streaming with bearer auth).
  // Inline the generated key directly so the user can copy the whole snippet
  // and paste it into their MCP client without further substitution.
  const mcpSampleConfig = $derived(
    `{
  "mcpServers": {
    "shellwatch": {
      "type": "http",
      "url": "${mcpUrl}",
      "headers": { "Authorization": "Bearer ${generatedKey || "<YOUR_API_KEY>"}" }
    }
  }
}`,
  );

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

  // --- Notifications step ---
  // Only probe the SW + push manager once. Re-firing on each back/forward
  // visit is harmless but wasteful — the user can't toggle from elsewhere
  // mid-wizard, so the first read is authoritative for the flow.
  let pushChecked = $state(false);
  $effect(() => {
    if (currentStep === "notifications" && pushSupported && !pushChecked) {
      pushChecked = true;
      void checkPushStatus();
    }
  });

  async function handleNotificationToggle() {
    error = "";
    try {
      if ($pushEnabled) {
        await unsubscribePush();
      } else {
        await subscribePush();
      }
    } catch (err) {
      error = (err as Error).message;
    }
  }

  function finish() {
    window.location.href = "/";
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
          <span class="check">✓</span> Passkey registered{registeredCred?.label
            ? ` as ${registeredCred.label}`
            : ""}. You can manage passkeys later in Settings.
        </p>
        <div class="nav-row">
          <button class="btn-secondary" onclick={back}>Back</button>
          <button class="btn-primary" onclick={next}>Continue</button>
        </div>
      {:else}
        <p class="description">
          This will be your primary authentication method. You can add more passkeys later in
          settings.
        </p>
        <div class="nav-row">
          <button class="btn-secondary" onclick={back}>Back</button>
          <button class="btn-primary" disabled={loading} onclick={handleRegisterPasskey}>
            Register Passkey
          </button>
        </div>
      {/if}
    {:else if currentStep === "server-setup"}
      <h1>Use this passkey for SSH</h1>
      <p class="description">
        Two one-time steps on each server you want to reach. Requires
        <strong>OpenSSH 8.4+</strong>.
      </p>

      {#if sshOneLiner && sshLine}
        <div class="code-block">
          <span class="code-label"
            >1. Enable WebAuthn keys in <code>/etc/ssh/sshd_config</code> (reload sshd after)</span
          >
          <code class="code-content">{SSHD_CONFIG_LINE}</code>
          <button
            class="btn-copy"
            onclick={(e) => copyToClipboard(SSHD_CONFIG_LINE, e.currentTarget as HTMLButtonElement)}
            >Copy</button
          >
        </div>

        <div class="code-block">
          <span class="code-label">2. Add this passkey to <code>~/.ssh/authorized_keys</code></span>
          <code class="code-content">{sshOneLiner}</code>
          <button
            class="btn-copy"
            onclick={(e) => copyToClipboard(sshOneLiner!, e.currentTarget as HTMLButtonElement)}
            >Copy</button
          >
        </div>
      {:else}
        <p class="hint">
          This authenticator does not expose an SSH-compatible public key. You can still use it for <Wordmark
          /> login. To enable SSH, register a different passkey from Settings.
        </p>
      {/if}

      <div class="nav-row">
        <button class="btn-secondary" onclick={back}>Back</button>
        <button class="btn-primary" onclick={next}>Continue</button>
      </div>
    {:else if currentStep === "endpoints"}
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
      </div>
      <div class="nav-row">
        <button class="btn-secondary" onclick={back}>Back</button>
        <button class="btn-primary" onclick={next}>
          {$endpoints.length > 0 ? "Continue" : "Skip"}
        </button>
      </div>
    {:else if currentStep === "mcp"}
      <h1>Connect AI agents</h1>
      <p class="description">
        Agents talk to <Wordmark /> via the Model Context Protocol. There are two ways to wire one up.
      </p>

      <div class="mcp-card">
        <div class="mcp-card-head">
          <span class="badge-recommended">Recommended</span>
          <strong>OAuth-capable agents</strong>
        </div>
        <p class="hint">
          Point your agent at this URL. The MCP client (Claude Desktop, Cursor, etc.) redirects
          through <Wordmark />'s OAuth flow — you approve with a passkey, and <Wordmark /> mints a scoped
          API key on the fly and injects it into the agent's session. No manual key handling.
        </p>
        <div class="code-block">
          <code class="code-content">{mcpUrl}</code>
          <button
            class="btn-copy"
            onclick={(e) => copyToClipboard(mcpUrl, e.currentTarget as HTMLButtonElement)}
            >Copy</button
          >
        </div>
      </div>

      {#if generatedKey}
        <!-- Success block lives outside <details> so collapsing can't hide a key
             that's shown only once. -->
        <div class="code-block code-block-success">
          <span class="code-label">API Key — copy now, shown only once</span>
          <code class="code-content">{generatedKey}</code>
          <button
            class="btn-copy"
            onclick={(e) => copyToClipboard(generatedKey, e.currentTarget as HTMLButtonElement)}
            >Copy</button
          >
        </div>
        <div class="code-block">
          <span class="code-label">Sample agent config</span>
          <pre class="code-content code-pre">{mcpSampleConfig}</pre>
          <button
            class="btn-copy"
            onclick={(e) => copyToClipboard(mcpSampleConfig, e.currentTarget as HTMLButtonElement)}
            >Copy</button
          >
        </div>
      {:else}
        <details class="extra" bind:open={showApiKeyForm}>
          <summary>Use a static API key instead</summary>
          <p class="hint">
            For non-OAuth agents, generate a key with <code>mcp</code> scope and configure your client
            with a bearer header.
          </p>
          <div class="form-row">
            <input
              type="text"
              class="input"
              bind:value={apiKeyLabel}
              placeholder="Agent name (e.g. claude-laptop)"
            />
            <button class="btn-secondary" disabled={loading} onclick={handleGenerateApiKey}>
              Generate
            </button>
          </div>
        </details>
      {/if}

      <div class="nav-row">
        <button class="btn-secondary" onclick={back}>Back</button>
        <button class="btn-primary" onclick={next}>Continue</button>
      </div>
    {:else if currentStep === "notifications"}
      <h1>Stay in the loop</h1>
      <p class="description">
        <Wordmark />'s value is the human-in-the-loop guard rail: when an agent (or another account)
        requests to open an SSH session to your endpoint, you get a push notification on this device
        and approve or deny — no terminal needed.
      </p>

      {#if !pushSupported}
        <div class="info-box">Push notifications are not supported in this browser.</div>
      {:else if !vapidConfigured}
        <div class="info-box">
          Push notifications are not configured on this server. Ask the admin to add a
          <code>vapid</code> section to <code>config.yaml</code>.
        </div>
      {:else}
        <div class="toggle-row">
          <button
            class="toggle"
            class:active={$pushEnabled}
            disabled={$pushLoading}
            onclick={handleNotificationToggle}
            aria-label="Push Notifications"
            role="switch"
            aria-checked={$pushEnabled}
          >
            <span class="toggle-knob"></span>
          </button>
          <span class="toggle-label">
            {#if $pushLoading}
              Updating…
            {:else if $pushEnabled}
              Enabled on this device
            {:else}
              Disabled
            {/if}
          </span>
        </div>
        <p class="hint">
          Toggle anytime from <strong>Settings → Notifications</strong>, on each device
          independently.
        </p>
      {/if}

      <div class="nav-row">
        <button class="btn-secondary" onclick={back}>Back</button>
        <button class="btn-primary" onclick={next}>Continue</button>
      </div>
    {:else if currentStep === "advanced"}
      <h1>What's next</h1>
      <p class="description">A few <Wordmark /> features worth knowing about.</p>

      <div class="advanced-list">
        <div class="advanced-item">
          <strong><code>shellwatch-agent</code></strong>
          <p>
            A local SSH agent that brokers signing through <Wordmark />. Run
            <code>ssh user@host</code> from your terminal — your passkey unlocks the connection, no private
            key on disk.
          </p>
        </div>
        <div class="advanced-item">
          <strong><code>pam_ssh_webauthn</code></strong>
          <p>
            PAM module that gates remote actions (e.g. <code>sudo</code>) on a passkey signature
            brokered through <Wordmark />.
          </p>
        </div>
        <div class="advanced-item">
          <strong>Docs &amp; guides</strong>
          <p>
            Setup walkthroughs and reference live at
            <a href="https://docs.shellwatch.ai" target="_blank" rel="noopener noreferrer"
              >docs.shellwatch.ai</a
            >.
          </p>
        </div>
      </div>

      <div class="nav-row">
        <button class="btn-secondary" onclick={back}>Back</button>
        <button class="btn-primary" onclick={finish}>Open ShellWatch</button>
      </div>
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

  .form-row {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 0.75rem;
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

  .endpoint-list {
    margin-bottom: 0.75rem;
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

  /* Reusable code-block surface used across server-setup, MCP, etc. */
  .code-block {
    position: relative;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    margin-bottom: 0.75rem;
    text-align: left;
  }

  .code-block-success {
    border-color: var(--green, #4ade80);
  }

  .code-label {
    display: block;
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
    margin-bottom: 0.35rem;
  }

  .code-content {
    display: block;
    font-size: 0.75rem;
    word-break: break-all;
    padding-right: 3.5rem; /* leave room for the absolute Copy button */
  }

  .code-pre {
    white-space: pre-wrap;
    margin: 0;
  }

  .code-block-success .code-content {
    color: var(--green, #4ade80);
  }

  .btn-copy {
    position: absolute;
    top: 0.4rem;
    right: 0.4rem;
    padding: 0.25rem 0.5rem;
    background: var(--bg-secondary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 0.7rem;
    cursor: pointer;
  }

  .btn-copy:hover {
    background: var(--border);
  }

  details.extra {
    text-align: left;
    margin-bottom: 0.75rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.5rem 0.75rem;
    background: var(--bg-primary);
  }

  details.extra summary {
    cursor: pointer;
    font-size: 0.78rem;
    font-weight: 500;
    color: var(--text-primary);
  }

  details.extra[open] summary {
    margin-bottom: 0.5rem;
  }

  /* MCP step */
  .mcp-card {
    text-align: left;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem;
    margin-bottom: 0.75rem;
  }

  .mcp-card-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.4rem;
    font-size: 0.9rem;
  }

  .badge-recommended {
    font-size: 0.6rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--accent);
    border: 1px solid var(--accent);
    border-radius: 4px;
    padding: 0.1rem 0.4rem;
  }

  /* Notifications step */
  .toggle-row {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
    margin-bottom: 0.5rem;
  }

  .toggle {
    position: relative;
    width: 40px;
    height: 22px;
    border-radius: 11px;
    border: 1px solid var(--border);
    background: var(--bg-primary);
    cursor: pointer;
    padding: 0;
    transition: background-color 0.2s;
  }

  .toggle.active {
    background: var(--green, #4ade80);
    border-color: var(--green, #4ade80);
  }

  .toggle-knob {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--text-muted);
    transition:
      transform 0.2s,
      background-color 0.2s;
  }

  .toggle.active .toggle-knob {
    transform: translateX(18px);
    background: white;
  }

  .toggle-label {
    font-size: 0.85rem;
    color: var(--text-primary);
  }

  .info-box {
    padding: 0.6rem 0.75rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 0.8rem;
    color: var(--text-muted);
    text-align: left;
    margin-bottom: 0.75rem;
  }

  /* Advanced step */
  .advanced-list {
    text-align: left;
    margin-bottom: 0.75rem;
  }

  .advanced-item {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    background: var(--bg-primary);
    margin-bottom: 0.5rem;
  }

  .advanced-item p {
    margin: 0.25rem 0 0;
    font-size: 0.78rem;
    color: var(--text-muted);
    line-height: 1.5;
  }

  .advanced-item a {
    color: var(--accent);
    text-decoration: none;
  }

  .advanced-item a:hover {
    text-decoration: underline;
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

    .form-row {
      flex-direction: column;
    }

    .btn-row {
      flex-direction: column;
    }

    .btn-row .btn-secondary {
      width: 100%;
    }

    .endpoint-item {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.15rem;
    }

    .code-content {
      font-size: 0.7rem;
    }
  }
</style>
