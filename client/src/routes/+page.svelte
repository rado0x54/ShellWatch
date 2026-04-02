<script lang="ts">
import { onDestroy } from "svelte";
import Terminal from "$lib/components/Terminal.svelte";
import { onWsMessage, type SessionMode, sessions } from "$lib/stores/ws.js";

let activeSessionId = $state<string | null>(null);
let modes = $state<Record<string, SessionMode>>({});

// Auto-attach to new sessions
const unsubscribe = onWsMessage((msg) => {
  if (msg.type === "sessions:changed") {
    const sessionIds = new Set(msg.sessions.map((s) => s.sessionId));
    // If active session was removed, clear it
    if (activeSessionId && !sessionIds.has(activeSessionId)) {
      activeSessionId = null;
    }
    // Auto-attach to newest session if none active
    if (!activeSessionId && msg.sessions.length > 0) {
      const newest = msg.sessions[msg.sessions.length - 1];
      activeSessionId = newest.sessionId;
      modes[newest.sessionId] = newest.mode;
    }
  }
});

onDestroy(unsubscribe);

export function attachSession(sessionId: string, mode: SessionMode = "control") {
  activeSessionId = sessionId;
  modes[sessionId] = mode;
}
</script>

<div class="terminal-page">
  {#if activeSessionId}
    {#each $sessions.filter((s) => s.sessionId === activeSessionId) as sess (sess.sessionId)}
      <Terminal
        sessionId={sess.sessionId}
        mode={modes[sess.sessionId] ?? sess.mode}
        onModeChange={(mode) => { modes[sess.sessionId] = mode; }}
      />
    {/each}
  {:else}
    <div class="placeholder">
      {#if $sessions.length === 0}
        <p>Select an endpoint to connect</p>
      {:else}
        <p>Select a session from the sidebar</p>
      {/if}
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
