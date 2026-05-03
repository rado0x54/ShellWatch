<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount, type Snippet } from "svelte";

  interface Props {
    title: string;
    onClose: () => void;
    onSubmit?: () => void;
    children: Snippet;
    actions?: Snippet;
    /** Tailwind-ish width hint (CSS value). Falls back to modal default. */
    width?: string;
  }

  let { title, onClose, onSubmit, children, actions, width }: Props = $props();

  let dialogEl: HTMLDivElement;

  function focusableElements(): HTMLElement[] {
    if (!dialogEl) return [];
    return Array.from(
      dialogEl.querySelectorAll<HTMLElement>(
        'input, select, textarea, button, [href], [tabindex]:not([tabindex="-1"])',
      ),
    ).filter((el) => !el.hasAttribute("disabled"));
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
      return;
    }
    if (e.key !== "Tab") return;
    const els = focusableElements();
    if (els.length === 0) return;
    const first = els[0];
    const last = els[els.length - 1];
    const active = document.activeElement as HTMLElement | null;
    if (e.shiftKey && active === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  }

  function handleOverlayClick(e: MouseEvent) {
    if (e.target === e.currentTarget) onClose();
  }

  function handleSubmit(e: SubmitEvent) {
    e.preventDefault();
    onSubmit?.();
  }

  onMount(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const focusables = focusableElements();
    const target =
      focusables.find((el) => el.tagName === "INPUT" || el.tagName === "TEXTAREA") ?? focusables[0];
    target?.focus();
    return () => previouslyFocused?.focus?.();
  });
</script>

<svelte:window onkeydown={handleKeydown} />

<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="modal-overlay" onclick={handleOverlayClick}>
  <div
    class="modal"
    role="dialog"
    aria-modal="true"
    aria-label={title}
    bind:this={dialogEl}
    style={width ? `width: ${width}; max-width: 90vw;` : ""}
  >
    {#if onSubmit}
      <form onsubmit={handleSubmit}>
        <h3>{title}</h3>
        {@render children()}
        {#if actions}
          <div class="modal-actions">{@render actions()}</div>
        {/if}
      </form>
    {:else}
      <h3>{title}</h3>
      {@render children()}
      {#if actions}
        <div class="modal-actions">{@render actions()}</div>
      {/if}
    {/if}
  </div>
</div>

<style>
  form {
    display: contents;
  }

  .modal-actions {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
    margin-top: 1.25rem;
  }
</style>
