<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { type Snippet } from "svelte";
  import Modal from "./Modal.svelte";

  interface Props {
    title: string;
    confirmLabel: string;
    onConfirm: () => void | Promise<void>;
    onCancel: () => void;
    children: Snippet;
    confirmDisabled?: boolean;
    processing?: boolean;
    width?: string;
  }

  let {
    title,
    confirmLabel,
    onConfirm,
    onCancel,
    children,
    confirmDisabled = false,
    processing = false,
    width,
  }: Props = $props();
</script>

<Modal {title} onClose={onCancel} onSubmit={onConfirm} {width}>
  {@render children()}
  {#snippet actions()}
    <button type="button" class="btn btn-secondary" onclick={onCancel} disabled={processing}>
      Cancel
    </button>
    <button type="submit" class="btn btn-primary" disabled={confirmDisabled || processing}>
      {processing ? "Working…" : confirmLabel}
    </button>
  {/snippet}
</Modal>
