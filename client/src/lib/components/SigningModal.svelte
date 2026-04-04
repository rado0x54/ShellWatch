<script lang="ts">
  import type { FidoSignRequest } from "$lib/utils/fido.js";
  import { handleFidoSignRequest } from "$lib/utils/fido.js";
  import { wsSend } from "$lib/stores/ws.js";

  interface Props {
    request: FidoSignRequest;
    onDone: () => void;
  }

  let { request, onDone }: Props = $props();
  let signing = $state(false);

  // TODO: show error feedback to user instead of silently dismissing (#31)
  async function handleSign() {
    signing = true;
    try {
      await handleFidoSignRequest(request);
    } finally {
      onDone();
    }
  }

  function handleSkip() {
    wsSend({ type: "fido:sign-skip", requestId: request.requestId });
    onDone();
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") handleSkip();
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="modal-overlay" onclick={handleSkip}>
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="modal" onclick={(e) => e.stopPropagation()}>
    <h3>Passkey Signature Request</h3>
    <div class="modal-fields">
      <div class="field">
        <span class="field-label">Endpoint</span>
        <span class="field-value">
          {request.endpointLabel ?? "Unknown"}
          {#if request.endpointAddress}
            <span class="address">({request.endpointAddress})</span>
          {/if}
        </span>
      </div>
      <div class="field">
        <span class="field-label">Passkey</span>
        <span class="field-value">{request.passkeyLabel ?? "Unknown"}</span>
      </div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick={handleSkip} disabled={signing}>Skip</button>
      <button class="btn btn-primary" onclick={handleSign} disabled={signing}>
        {#if signing}Signing...{:else}Sign{/if}
      </button>
    </div>
  </div>
</div>

<style>
  .modal-fields {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin: 1rem 0;
  }

  .field {
    display: flex;
    gap: 0.75rem;
    align-items: baseline;
  }

  .field-label {
    font-size: 0.8rem;
    color: var(--text-muted);
    min-width: 5rem;
  }

  .field-value {
    font-size: 0.9rem;
  }

  .address {
    color: var(--text-muted);
    font-size: 0.8rem;
  }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1rem;
  }
</style>
