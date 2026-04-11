<script lang="ts">
  import { toasts, removeToast, toastError, type SignRequestAction } from "$lib/stores/toasts.js";
  import {
    approveAction,
    performSignCeremony,
    resolveAction,
    sourceLabels,
  } from "$lib/utils/webauthn-sign.js";

  let activeActionId = $state<string | null>(null);

  async function handleAction(action: SignRequestAction, toastId: string) {
    activeActionId = action.actionId;
    try {
      if (action.actionType === "webauthn-sign") {
        const result = await performSignCeremony(action);
        await resolveAction(action.actionId, result);
      } else {
        await approveAction(action.actionId);
      }
      removeToast(toastId);
    } catch (err) {
      const verb = action.actionType === "key-approve" ? "Approval" : "Signing";
      toastError(`${verb} failed: ${(err as Error).message}`);
    } finally {
      activeActionId = null;
    }
  }

  async function handleDeny(actionId: string, toastId: string) {
    try {
      const res = await fetch(`/api/actions/${actionId}/deny`, { method: "POST" });
      if (!res.ok) {
        toastError(`Failed to deny action: ${await res.text()}`);
      }
    } catch (err) {
      toastError(`Failed to deny action: ${(err as Error).message}`);
    }
    removeToast(toastId);
  }
</script>

{#if $toasts.length > 0}
  <div class="toast-container">
    {#each $toasts as toast (toast.id)}
      <div class="toast toast-{toast.variant}">
        {#if toast.variant === "sign-request" && toast.action}
          {@const isProcessing = activeActionId === toast.action.actionId}
          {@const isKeyApprove = toast.action.actionType === "key-approve"}
          <div class="toast-header">
            <span class="toast-icon">{isKeyApprove ? "&#128272;" : "&#128273;"}</span>
            <span class="toast-title">
              {isKeyApprove ? "SSH Key Approval Request" : "Passkey Signature Request"}
            </span>
          </div>
          <div class="toast-body">
            <div class="toast-field">
              <span class="toast-label">Source</span>
              <span class="toast-value"
                >{sourceLabels[toast.action.source] ?? toast.action.source}</span
              >
            </div>
            {#if toast.action.endpointLabel}
              <div class="toast-field">
                <span class="toast-label">Endpoint</span>
                <span class="toast-value">
                  {toast.action.endpointLabel}
                  {#if toast.action.endpointAddress}
                    <span class="toast-muted">({toast.action.endpointAddress})</span>
                  {/if}
                </span>
              </div>
            {/if}
            {#if toast.action.actionType === "key-approve"}
              <div class="toast-field">
                <span class="toast-label">SSH Key</span>
                <span class="toast-value">{toast.action.keyLabel}</span>
              </div>
              {#if toast.action.keyFingerprint}
                <div class="toast-field">
                  <span class="toast-label">Fingerprint</span>
                  <span class="toast-value toast-mono">{toast.action.keyFingerprint}</span>
                </div>
              {/if}
            {/if}
            {#if toast.action.actionType === "webauthn-sign" && toast.action.passkeyLabel}
              <div class="toast-field">
                <span class="toast-label">Passkey</span>
                <span class="toast-value">{toast.action.passkeyLabel}</span>
              </div>
            {/if}
          </div>
          <div class="toast-actions">
            <button
              class="btn btn-secondary"
              onclick={() => handleDeny(toast.action!.actionId, toast.id)}
              disabled={isProcessing}
            >
              Deny
            </button>
            <button
              class="btn btn-primary"
              onclick={() => handleAction(toast.action!, toast.id)}
              disabled={isProcessing}
            >
              {#if isProcessing}
                {isKeyApprove ? "Approving..." : "Signing..."}
              {:else}
                {isKeyApprove ? "Approve" : "Sign"}
              {/if}
            </button>
          </div>
        {:else}
          <div class="toast-simple">
            {#if toast.variant === "error"}
              <span class="toast-icon toast-icon-error">&#10007;</span>
            {:else}
              <span class="toast-icon toast-icon-info">&#8505;</span>
            {/if}
            <span class="toast-message">{toast.message}</span>
            <button class="toast-close" onclick={() => removeToast(toast.id)}>&#10005;</button>
          </div>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<style>
  .toast-container {
    position: fixed;
    top: 1rem;
    right: 1rem;
    z-index: 2000;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    max-width: 400px;
    pointer-events: none;
  }

  .toast {
    pointer-events: auto;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    animation: slide-in 0.2s ease-out;
  }

  .toast-error {
    border-color: var(--red);
  }

  .toast-sign-request {
    border-color: var(--accent);
  }

  .toast-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
  }

  .toast-title {
    font-size: 0.85rem;
    font-weight: 600;
  }

  .toast-icon {
    font-size: 0.9rem;
  }

  .toast-icon-error {
    color: var(--red);
  }

  .toast-icon-info {
    color: var(--accent);
  }

  .toast-body {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin-bottom: 0.75rem;
  }

  .toast-field {
    display: flex;
    gap: 0.5rem;
    align-items: baseline;
  }

  .toast-label {
    font-size: 0.7rem;
    color: var(--text-muted);
    min-width: 4.5rem;
  }

  .toast-value {
    font-size: 0.8rem;
  }

  .toast-muted {
    color: var(--text-muted);
    font-size: 0.75rem;
  }

  .toast-mono {
    font-family: monospace;
    font-size: 0.75rem;
  }

  .toast-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }

  .toast-simple {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .toast-message {
    flex: 1;
    font-size: 0.8rem;
  }

  .toast-close {
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 0.8rem;
    padding: 0.2rem;
    line-height: 1;
  }

  .toast-close:hover {
    color: var(--text-primary);
  }

  @keyframes slide-in {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }
</style>
