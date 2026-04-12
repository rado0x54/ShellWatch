<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/stores";
  import { onMount } from "svelte";
  import { clearAction, toastError, toastInfo } from "$lib/stores/toasts.js";
  import {
    approveAction,
    performSignCeremony,
    resolveAction,
    sourceLabels,
    triggerKindLabels,
  } from "$lib/utils/webauthn-sign.js";

  const actionId = $derived($page.params.id);

  type EndpointAuthTrigger =
    | { kind: "ui"; sourceIp: string }
    | { kind: "mcp"; sourceIp: string; mcpClientName?: string; mcpClientVersion?: string };

  type SignContext =
    | { source: "agent-proxy"; sourceIp: string; apiKeyPrefix: string }
    | {
        source: "endpoint-auth";
        endpointLabel: string;
        endpointAddress: string;
        trigger: EndpointAuthTrigger;
      }
    | {
        source: "agent-forwarding";
        endpointLabel: string;
        endpointAddress: string;
        sessionId: string;
      };

  interface ActionData {
    id: string;
    type: "webauthn-sign" | "key-approve";
    accountId: string;
    status: string;
    createdAt: number;
    expiresAt: number;
    context: SignContext;
    redirectTo?: string;
    // webauthn-sign fields
    credentialId?: string;
    challenge?: string;
    rpId?: string;
    passkeyLabel?: string;
    // key-approve fields
    keyLabel?: string;
    keyFingerprint?: string;
  }

  let action = $state<ActionData | null>(null);
  let loading = $state(true);
  let processing = $state(false);
  let error = $state<string | null>(null);
  let resultStatus = $state<string | null>(null);

  const isKeyApprove = $derived(action?.type === "key-approve");

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

  async function handleAction() {
    if (!action) return;
    processing = true;
    error = null;

    try {
      let response;
      if (action.type === "key-approve") {
        response = await approveAction(actionId);
      } else {
        const result = await performSignCeremony(
          action as { credentialId: string; challenge: string; rpId: string },
        );
        response = await resolveAction(actionId, result);
      }
      resultStatus = "completed";
      clearAction(actionId);
      toastInfo(isKeyApprove ? "Key usage approved" : "Signature completed successfully");
      if (response.redirectTo && isSafeRedirect(response.redirectTo)) {
        // Server-computed path (e.g. /terminal/:id). Use window.location
        // since typed routes can't validate a runtime string.
        window.location.href = response.redirectTo;
      }
    } catch (err) {
      error = (err as Error).message;
      toastError(`${isKeyApprove ? "Approval" : "Signing"} failed: ${error}`);
    } finally {
      processing = false;
    }
  }

  function isSafeRedirect(path: string): boolean {
    return path.startsWith("/") && !path.startsWith("//");
  }

  async function handleDeny() {
    if (!action) return;
    try {
      const res = await fetch(`/api/actions/${actionId}/deny`, { method: "POST" });
      if (res.ok) {
        resultStatus = "denied";
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

  const ctx = $derived(action?.context);
  const displayStatus = $derived(resultStatus ?? action?.status);
  const isTerminal = $derived(displayStatus !== "pending");
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
  {:else if isTerminal}
    <div class="sign-card">
      <h2>
        {#if displayStatus === "completed"}
          {isKeyApprove ? "Key Usage Approved" : "Signature Complete"}
        {:else if displayStatus === "denied"}
          Request Denied
        {:else if displayStatus === "expired"}
          Request Expired
        {:else}
          Request {displayStatus}
        {/if}
      </h2>
      <p class="sign-status-msg">
        {#if displayStatus === "completed"}
          {isKeyApprove
            ? "The SSH key usage was approved successfully."
            : "The passkey signature was completed successfully."}
        {:else if displayStatus === "denied"}
          This request was denied.
        {:else if displayStatus === "expired"}
          This request expired before it could be completed.
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
      <h2>{isKeyApprove ? "SSH Key Approval Request" : "Passkey Signature Request"}</h2>

      <div class="sign-fields">
        <div class="sign-field">
          <span class="sign-label">Source</span>
          <span class="sign-value">{sourceLabels[ctx!.source] ?? ctx!.source}</span>
        </div>

        {#if ctx && (ctx.source === "endpoint-auth" || ctx.source === "agent-forwarding")}
          <div class="sign-field">
            <span class="sign-label">Endpoint</span>
            <span class="sign-value">
              {ctx.endpointLabel}
              <span class="sign-muted">({ctx.endpointAddress})</span>
            </span>
          </div>
        {/if}

        {#if ctx && ctx.source === "endpoint-auth"}
          <div class="sign-field">
            <span class="sign-label">Triggered by</span>
            <span class="sign-value">
              {triggerKindLabels[ctx.trigger.kind] ?? ctx.trigger.kind}
              {#if ctx.trigger.sourceIp}
                <span class="sign-muted sign-mono">({ctx.trigger.sourceIp})</span>
              {/if}
            </span>
          </div>
          {#if ctx.trigger.kind === "mcp" && ctx.trigger.mcpClientName}
            <div class="sign-field">
              <span class="sign-label">MCP Client</span>
              <span class="sign-value">
                {ctx.trigger.mcpClientName}
                {#if ctx.trigger.mcpClientVersion}
                  <span class="sign-muted">v{ctx.trigger.mcpClientVersion}</span>
                {/if}
              </span>
            </div>
          {/if}
        {/if}

        {#if ctx && ctx.source === "agent-proxy"}
          <div class="sign-field">
            <span class="sign-label">Source IP</span>
            <span class="sign-value sign-mono">{ctx.sourceIp}</span>
          </div>
          <div class="sign-field">
            <span class="sign-label">API Key</span>
            <span class="sign-value sign-mono">{ctx.apiKeyPrefix}...</span>
          </div>
        {/if}

        {#if isKeyApprove && action.keyLabel}
          <div class="sign-field">
            <span class="sign-label">SSH Key</span>
            <span class="sign-value">{action.keyLabel}</span>
          </div>
          {#if action.keyFingerprint}
            <div class="sign-field">
              <span class="sign-label">Fingerprint</span>
              <span class="sign-value sign-mono">{action.keyFingerprint}</span>
            </div>
          {/if}
        {/if}

        {#if !isKeyApprove && action.passkeyLabel}
          <div class="sign-field">
            <span class="sign-label">Passkey</span>
            <span class="sign-value">{action.passkeyLabel}</span>
          </div>
        {/if}

        {#if ctx && ctx.source === "agent-forwarding" && ctx.sessionId}
          <div class="sign-field">
            <span class="sign-label">Session</span>
            <button class="sign-link" onclick={() => viewSession(ctx.sessionId)}>
              View Session
            </button>
          </div>
        {/if}
      </div>

      {#if error}
        <div class="sign-error">{error}</div>
      {/if}

      <div class="sign-actions">
        <button class="btn btn-secondary" onclick={handleDeny} disabled={processing}>Deny</button>
        <button class="btn btn-primary" onclick={handleAction} disabled={processing}>
          {#if processing}
            {isKeyApprove ? "Approving..." : "Signing..."}
          {:else}
            {isKeyApprove ? "Approve" : "Sign"}
          {/if}
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
