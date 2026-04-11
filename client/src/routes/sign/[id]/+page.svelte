<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/stores";
  import { onMount } from "svelte";
  import { toastError, toastInfo } from "$lib/stores/toasts.js";
  import { clearAction } from "$lib/stores/toasts.js";

  const actionId = $derived($page.params.id);

  interface ActionData {
    id: string;
    type: string;
    accountId: string;
    status: string;
    createdAt: number;
    expiresAt: number;
    context: {
      source: string;
      sourceIp?: string;
      apiKeyPrefix?: string;
      endpointLabel?: string;
      endpointAddress?: string;
      sessionId?: string;
      mcpClientName?: string;
      mcpClientVersion?: string;
    };
    credentialId: string;
    challenge: string;
    rpId: string;
    passkeyLabel?: string;
  }

  let action = $state<ActionData | null>(null);
  let loading = $state(true);
  let signing = $state(false);
  let error = $state<string | null>(null);
  let done = $state(false);

  const sourceLabels: Record<string, string> = {
    "agent-proxy": "Agent Proxy",
    ui: "SSH Connection",
    mcp: "MCP Client",
    "forwarding-agent": "Agent Forwarding",
  };

  onMount(async () => {
    try {
      const res = await fetch(`/api/actions/${actionId}`);
      if (res.status === 401) {
        await goto(resolve(`/login?redirect=/sign/${actionId}`));
        return;
      }
      if (!res.ok) {
        error = "Action not found";
        return;
      }
      action = await res.json();
    } catch {
      error = "Failed to load action";
    } finally {
      loading = false;
    }
  });

  function bufferToBase64url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function handleSign() {
    if (!action) return;
    signing = true;
    error = null;

    try {
      // Decode challenge (standard base64)
      const decoded = atob(action.challenge);
      const challengeBytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));

      // Decode credential ID (base64url)
      const credIdBytes = Uint8Array.from(
        atob(action.credentialId.replace(/-/g, "+").replace(/_/g, "/")),
        (c) => c.charCodeAt(0),
      );

      const assertion = (await navigator.credentials.get({
        publicKey: {
          challenge: challengeBytes,
          rpId: action.rpId,
          allowCredentials: [
            {
              id: credIdBytes,
              type: "public-key",
              transports: ["usb", "nfc", "ble", "internal"],
            },
          ],
          userVerification: "discouraged",
          timeout: 60000,
        },
      })) as PublicKeyCredential;

      if (!assertion?.response) {
        throw new Error("No assertion returned");
      }

      const authResponse = assertion.response as AuthenticatorAssertionResponse;

      const res = await fetch(`/api/actions/${actionId}/resolve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          authenticatorData: bufferToBase64url(authResponse.authenticatorData),
          signature: bufferToBase64url(authResponse.signature),
          clientDataJSON: new TextDecoder().decode(authResponse.clientDataJSON),
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: "Unknown error" }));
        throw new Error(body.error ?? `HTTP ${res.status}`);
      }

      done = true;
      action.status = "completed";
      clearAction(actionId);
      toastInfo("Signature completed successfully");
    } catch (err) {
      error = (err as Error).message;
      toastError(`Signing failed: ${error}`);
    } finally {
      signing = false;
    }
  }

  async function handleDeny() {
    if (!action) return;
    try {
      const res = await fetch(`/api/actions/${actionId}/deny`, {
        method: "POST",
      });
      if (res.ok) {
        action.status = "denied";
        done = true;
        clearAction(actionId);
      } else {
        const body = await res.json().catch(() => ({ error: "Unknown error" }));
        error = body.error ?? "Failed to deny";
      }
    } catch (err) {
      error = (err as Error).message;
    }
  }

  function viewSession(sessionId: string) {
    goto(resolve(`/session/${sessionId}`));
  }
</script>

<div class="sign-page">
  {#if loading}
    <div class="sign-card">
      <p class="sign-loading">Loading...</p>
    </div>
  {:else if !action}
    <div class="sign-card">
      <h2>Action Not Found</h2>
      <p class="sign-status-msg">{error ?? "This action does not exist or has expired."}</p>
      <div class="sign-actions">
        <button class="btn btn-primary" onclick={() => goto(resolve("/"))}>Go Home</button>
      </div>
    </div>
  {:else if action.status !== "pending" || done}
    <div class="sign-card">
      <h2>
        {#if action.status === "completed"}
          Signature Complete
        {:else if action.status === "denied"}
          Request Denied
        {:else if action.status === "expired"}
          Request Expired
        {:else}
          Request {action.status}
        {/if}
      </h2>
      <p class="sign-status-msg">
        {#if action.status === "completed"}
          The passkey signature was completed successfully.
        {:else if action.status === "denied"}
          This signing request was denied.
        {:else if action.status === "expired"}
          This signing request expired before it could be completed.
        {:else}
          This request is no longer pending.
        {/if}
      </p>
      <div class="sign-actions">
        <button class="btn btn-primary" onclick={() => goto(resolve("/"))}>Go Home</button>
      </div>
    </div>
  {:else}
    <div class="sign-card">
      <h2>Passkey Signature Request</h2>

      <div class="sign-fields">
        <div class="sign-field">
          <span class="sign-label">Source</span>
          <span class="sign-value"
            >{sourceLabels[action.context.source] ?? action.context.source}</span
          >
        </div>

        {#if action.context.endpointLabel}
          <div class="sign-field">
            <span class="sign-label">Endpoint</span>
            <span class="sign-value">
              {action.context.endpointLabel}
              {#if action.context.endpointAddress}
                <span class="sign-muted">({action.context.endpointAddress})</span>
              {/if}
            </span>
          </div>
        {/if}

        {#if action.context.sourceIp}
          <div class="sign-field">
            <span class="sign-label">Source IP</span>
            <span class="sign-value sign-mono">{action.context.sourceIp}</span>
          </div>
        {/if}

        {#if action.context.apiKeyPrefix}
          <div class="sign-field">
            <span class="sign-label">API Key</span>
            <span class="sign-value sign-mono">{action.context.apiKeyPrefix}...</span>
          </div>
        {/if}

        {#if action.context.mcpClientName}
          <div class="sign-field">
            <span class="sign-label">MCP Client</span>
            <span class="sign-value">
              {action.context.mcpClientName}
              {#if action.context.mcpClientVersion}
                <span class="sign-muted">v{action.context.mcpClientVersion}</span>
              {/if}
            </span>
          </div>
        {/if}

        {#if action.passkeyLabel}
          <div class="sign-field">
            <span class="sign-label">Passkey</span>
            <span class="sign-value">{action.passkeyLabel}</span>
          </div>
        {/if}

        {#if action.context.sessionId && action.context.sessionId !== "pending"}
          <div class="sign-field">
            <span class="sign-label">Session</span>
            <button class="sign-link" onclick={() => viewSession(action!.context.sessionId!)}>
              View Session
            </button>
          </div>
        {/if}
      </div>

      {#if error}
        <div class="sign-error">{error}</div>
      {/if}

      <div class="sign-actions">
        <button class="btn btn-secondary" onclick={handleDeny} disabled={signing}>Deny</button>
        <button class="btn btn-primary" onclick={handleSign} disabled={signing}>
          {#if signing}Signing...{:else}Sign{/if}
        </button>
      </div>
    </div>
  {/if}
</div>

<style>
  .sign-page {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100%;
    padding: 2rem;
  }

  .sign-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem;
    min-width: 360px;
    max-width: 500px;
    width: 100%;
  }

  .sign-card h2 {
    font-size: 1.1rem;
    font-weight: 600;
    margin-bottom: 1.25rem;
  }

  .sign-loading {
    color: var(--text-muted);
    text-align: center;
    padding: 2rem 0;
  }

  .sign-status-msg {
    color: var(--text-muted);
    font-size: 0.9rem;
    margin-bottom: 1.5rem;
  }

  .sign-fields {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    margin-bottom: 1.5rem;
  }

  .sign-field {
    display: flex;
    gap: 0.75rem;
    align-items: baseline;
  }

  .sign-label {
    font-size: 0.75rem;
    color: var(--text-muted);
    min-width: 5.5rem;
    flex-shrink: 0;
  }

  .sign-value {
    font-size: 0.9rem;
  }

  .sign-muted {
    color: var(--text-muted);
    font-size: 0.8rem;
  }

  .sign-mono {
    font-family: monospace;
    font-size: 0.85rem;
  }

  .sign-link {
    background: none;
    border: none;
    color: var(--accent);
    cursor: pointer;
    font-size: 0.85rem;
    text-decoration: underline;
    padding: 0;
  }

  .sign-link:hover {
    color: var(--accent-hover);
  }

  .sign-error {
    background: rgba(248, 113, 113, 0.1);
    border: 1px solid rgba(248, 113, 113, 0.3);
    border-radius: 6px;
    padding: 0.6rem 0.75rem;
    font-size: 0.8rem;
    color: var(--red);
    margin-bottom: 1rem;
  }

  .sign-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }
</style>
