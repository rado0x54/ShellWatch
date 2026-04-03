<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/stores";
  import Terminal from "$lib/components/Terminal.svelte";
  import { type SessionMode, sessions } from "$lib/stores/ws.js";

  let modes = $state<Record<string, SessionMode>>({});

  const sessionId = $derived($page.params.id);
  const session = $derived($sessions.find((s) => s.sessionId === sessionId));

  // Navigate home when session is removed from the list
  let wasFound = $state(false);
  $effect(() => {
    if (session) {
      wasFound = true;
    } else if (wasFound) {
      goto(resolve("/"), { replaceState: true });
    }
  });
</script>

<div class="terminal-page">
  {#if session}
    <Terminal
      sessionId={session.sessionId}
      mode={modes[session.sessionId] ?? session.mode}
      onModeChange={(mode) => {
        modes[session.sessionId] = mode;
      }}
    />
  {:else}
    <div class="placeholder">
      <p>Session not found</p>
    </div>
  {/if}
</div>

<style>
  .terminal-page {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    position: relative;
    overflow: hidden;
  }

  .placeholder {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: #555;
    font-size: 1.1rem;
  }
</style>
