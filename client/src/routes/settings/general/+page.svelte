<script lang="ts">
  import { onMount } from "svelte";
  import Identicon from "$lib/components/Identicon.svelte";
  import { account, fetchAccount, updateAccountName } from "$lib/stores/account.js";

  let nameInput = $state("");
  let saving = $state(false);
  let message = $state("");

  onMount(async () => {
    await fetchAccount();
    if ($account) {
      nameInput = $account.name;
    }
  });

  async function handleSave() {
    if (!nameInput.trim()) {
      message = "Name cannot be empty";
      return;
    }
    saving = true;
    message = "";
    try {
      await updateAccountName(nameInput.trim());
      message = "Saved";
      setTimeout(() => (message = ""), 2000);
    } catch (err) {
      message = (err as Error).message;
    }
    saving = false;
  }
</script>

<section>
  <h2>General</h2>

  {#if $account}
    <div class="account-section">
      <div class="account-header">
        <Identicon uuid={$account.id} size={48} />
        <div class="account-meta">
          <span class="account-type">{$account.isAdmin ? "Admin" : "User"}</span>
          <span class="account-id">{$account.id}</span>
        </div>
      </div>

      <div class="field">
        <label for="account-name">Account Name</label>
        <div class="field-row">
          <input id="account-name" type="text" bind:value={nameInput} />
          <button class="btn btn-primary" disabled={saving} onclick={handleSave}>Save</button>
        </div>
        {#if message}
          <span class="message" class:success={message === "Saved"}>{message}</span>
        {/if}
      </div>
    </div>
  {/if}
</section>

<style>
  h2 {
    font-size: 0.75rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .account-section {
    max-width: 480px;
  }

  .account-header {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1.5rem;
    padding: 1rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 8px;
  }

  .account-meta {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .account-type {
    font-weight: 600;
    font-size: 0.85rem;
  }

  .account-id {
    font-size: 0.7rem;
    color: var(--text-muted);
    font-family: monospace;
  }

  .field {
    margin-bottom: 1rem;
  }

  .field label {
    display: block;
    font-size: 0.8rem;
    font-weight: 500;
    margin-bottom: 0.375rem;
    color: var(--text-muted);
  }

  .field-row {
    display: flex;
    gap: 0.5rem;
  }

  .field-row input {
    flex: 1;
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg-primary);
    color: var(--text-primary);
    font-size: 0.85rem;
  }

  .message {
    display: block;
    font-size: 0.8rem;
    margin-top: 0.375rem;
    color: var(--red);
  }

  .message.success {
    color: var(--green, #4ade80);
  }
</style>
