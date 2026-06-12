<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { onMount } from "svelte";
  import { resolve } from "$app/paths";
  import { handleCallback } from "$lib/oauth.js";

  let error = $state("");

  onMount(async () => {
    try {
      const returnTo = await handleCallback();
      // Full navigation so the app boots fresh with the new token in memory.
      window.location.href = returnTo;
    } catch (err) {
      error = (err as Error).message;
    }
  });
</script>

<div class="callback-page">
  {#if error}
    <div class="card">
      <h1>Sign-in failed</h1>
      <p class="error">{error}</p>
      <a href={resolve("/")}>Back to sign in</a>
    </div>
  {:else}
    <p class="status">Completing sign-in…</p>
  {/if}
</div>

<style>
  .callback-page {
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--surface-dim);
  }
  .card {
    background: var(--surface-container-low);
    padding: var(--space-7);
    text-align: center;
    max-width: 380px;
    width: 90%;
  }
  .status {
    color: var(--on-surface-variant);
  }
  .error {
    color: var(--error);
    margin: 0.75rem 0;
  }
</style>
