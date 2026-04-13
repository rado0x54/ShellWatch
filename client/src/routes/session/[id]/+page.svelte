<script lang="ts">
  import { goto } from "$app/navigation";
  import { resolve } from "$app/paths";
  import { page } from "$app/state";
  import Terminal from "$lib/components/Terminal.svelte";
  import { type SessionMode, sessions } from "$lib/stores/ws.js";
  import type { PageProps } from "./$types";

  let modes = $state<Record<string, SessionMode>>({});

  const sessionId = $derived((page.params as PageProps["params"]).id);
  const session = $derived($sessions.find((s) => s.sessionId === sessionId));

  // Clean up stale mode entries when navigating away from a session
  let prevSessionId = $state<string | null>(null);
  $effect(() => {
    if (prevSessionId && prevSessionId !== sessionId) {
      delete modes[prevSessionId];
    }
    prevSessionId = sessionId;
  });

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
    {#key session.sessionId}
      <Terminal
        sessionId={session.sessionId}
        mode={modes[session.sessionId] ?? session.mode}
        onModeChange={(mode) => {
          modes[session.sessionId] = mode;
        }}
      />
    {/key}
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
