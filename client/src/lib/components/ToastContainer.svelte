<script lang="ts">
  import { toasts, removeToast, toastError, type SignRequestAction } from "$lib/stores/toasts.js";
  import { errorMessage } from "$lib/utils/error-message.js";
  import {
    approveAction,
    performSignCeremony,
    resolveAction,
    sourceLabels,
  } from "$lib/utils/webauthn-sign.js";

  let activeActionId = $state<string | null>(null);

  // Collapse the middle of a long identifier for compact toast display.
  // Preserves a `prefix:` (e.g. `SHA256:`) when present.
  function shortFingerprint(s: string, head = 8, tail = 8): string {
    const colon = s.indexOf(":");
    const [prefix, body] = colon === -1 ? ["", s] : [s.slice(0, colon + 1), s.slice(colon + 1)];
    return body.length > head + tail + 1
      ? `${prefix}${body.slice(0, head)}…${body.slice(-tail)}`
      : `${prefix}${body}`;
  }

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
      console.error(`${verb} failed:`, err);
      toastError(`${verb} failed: ${errorMessage(err)}`);
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
      console.error("Failed to deny action:", err);
      toastError(`Failed to deny action: ${errorMessage(err)}`);
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
            <span class="toast-icon">{isKeyApprove ? "🔐" : "🔑"}</span>
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
                  <span class="toast-value toast-mono" title={toast.action.keyFingerprint}
                    >{shortFingerprint(toast.action.keyFingerprint)}</span
                  >
                </div>
              {/if}
            {/if}
            {#if toast.action.actionType === "webauthn-sign"}
              {#if toast.action.passkeyLabel}
                <div class="toast-field">
                  <span class="toast-label">Passkey</span>
                  <span class="toast-value">{toast.action.passkeyLabel}</span>
                </div>
              {/if}
              <div class="toast-field">
                <span class="toast-label">Fingerprint</span>
                <span class="toast-value toast-mono" title={toast.action.credentialId}
                  >{shortFingerprint(toast.action.credentialId)}</span
                >
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
    background: rgba(44, 44, 44, 0.6);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid var(--outline-variant);
    padding: var(--space-4) var(--space-5);
    animation: slide-in 0.2s ease-out;
  }

  .toast-error {
    box-shadow: var(--glow-error);
    border-color: rgba(255, 90, 90, 0.25);
  }

  .toast-sign-request {
    box-shadow: var(--glow-primary-strong);
    border-color: rgba(105, 246, 184, 0.25);
  }

  .toast-header {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }

  .toast-title {
    font-family: var(--font-display);
    font-size: var(--body-md);
    font-weight: 600;
    letter-spacing: -0.01em;
    color: var(--on-surface);
  }

  .toast-icon {
    font-size: 1rem;
  }

  .toast-icon-error {
    color: var(--error);
  }

  .toast-icon-info {
    color: var(--primary);
  }

  .toast-body {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    margin-bottom: var(--space-4);
  }

  .toast-field {
    display: flex;
    gap: var(--space-3);
    align-items: baseline;
  }

  .toast-label {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--on-surface-variant);
    min-width: 5.5rem;
  }

  .toast-value {
    font-size: var(--body-md);
    color: var(--on-surface);
  }

  .toast-muted {
    color: var(--on-surface-variant);
    font-size: var(--label-md);
  }

  .toast-mono {
    font-family: var(--font-mono);
    font-size: var(--label-md);
    color: var(--primary);
  }

  .toast-actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-3);
  }

  .toast-simple {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .toast-message {
    flex: 1;
    font-size: var(--body-md);
    color: var(--on-surface);
  }

  .toast-close {
    background: none;
    border: none;
    color: var(--on-surface-variant);
    cursor: pointer;
    font-size: var(--body-md);
    padding: var(--space-1);
    line-height: 1;
  }

  .toast-close:hover {
    color: var(--primary);
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

  @keyframes slide-up {
    from {
      transform: translateY(100%);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }

  /* ----------------------------------------------------------------
   * Mobile — bottom sheet: stack fields, full-width actions, slide-up
   * ---------------------------------------------------------------- */
  @media (max-width: 768px) {
    .toast-container {
      top: auto;
      left: var(--space-3);
      right: var(--space-3);
      bottom: var(--space-3);
      max-width: none;
      flex-direction: column-reverse;
    }

    .toast {
      animation: slide-up 0.2s ease-out;
      padding: var(--space-5);
    }

    .toast-field {
      flex-direction: column;
      gap: var(--space-1);
      align-items: stretch;
    }

    .toast-label {
      min-width: 0;
    }

    .toast-mono {
      word-break: break-all;
      overflow-wrap: anywhere;
    }

    .toast-actions {
      justify-content: stretch;
      gap: var(--space-3);
    }

    .toast-actions :global(.btn) {
      flex: 1;
      padding: var(--space-4);
      font-size: var(--body-md);
    }
  }
</style>
