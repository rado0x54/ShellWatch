<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { FitAddon } from "@xterm/addon-fit";
  import { Terminal } from "@xterm/xterm";
  import { onDestroy, onMount } from "svelte";
  import { SvelteMap } from "svelte/reactivity";
  import { endpoints } from "$lib/stores/endpoints.js";
  import { onWsMessage, type SessionListEntry, sessions, wsAttach } from "$lib/stores/ws.js";

  interface ObservedTerminal {
    sessionId: string;
    label: string;
    terminal: Terminal;
    fitAddon: FitAddon;
  }

  let gridEl: HTMLDivElement;
  let observed = new SvelteMap<string, ObservedTerminal>();
  let resizeObserver: ResizeObserver | null = null;
  let unsubscribe: (() => void) | null = null;

  function getEndpointLabel(endpointId: string): string {
    const ep = $endpoints.find((e) => e.id === endpointId);
    return ep?.label ?? endpointId;
  }

  function getGridDimensions(count: number): { cols: number; rows: number } {
    if (count <= 1) return { cols: 1, rows: 1 };
    if (count <= 2) return { cols: 2, rows: 1 };
    if (count <= 4) return { cols: 2, rows: 2 };
    if (count <= 6) return { cols: 3, rows: 2 };
    if (count <= 9) return { cols: 3, rows: 3 };
    if (count <= 12) return { cols: 4, rows: 3 };
    return { cols: 4, rows: 4 };
  }

  function fitAll() {
    for (const obs of observed.values()) {
      try {
        obs.fitAddon.fit();
      } catch {
        /* not rendered yet */
      }
    }
  }

  function syncSessions(sessionList: SessionListEntry[]) {
    if (!gridEl) return;

    const currentIds = new Set(observed.keys());
    const newIds = new Set(sessionList.map((s) => s.sessionId));

    // Remove closed sessions
    for (const id of currentIds) {
      if (!newIds.has(id)) {
        const obs = observed.get(id)!;
        obs.terminal.dispose();
        observed.delete(id);
      }
    }

    // Add new sessions
    for (const sess of sessionList) {
      if (!observed.has(sess.sessionId)) {
        const label = getEndpointLabel(sess.endpointId);
        const terminal = new Terminal({
          cursorBlink: false,
          fontSize: 11,
          fontFamily:
            "'Geist Mono', 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace",
          theme: {
            background: "#0e0e0e",
            foreground: "#f2f2f2",
            cursor: "#69f6b8",
            selectionBackground: "rgba(105, 246, 184, 0.25)",
            green: "#69f6b8",
            yellow: "#f8a010",
            red: "#ff5a5a",
            brightGreen: "#69f6b8",
            brightYellow: "#f8a010",
            brightRed: "#ff5a5a",
            brightWhite: "#f2f2f2",
          },
          disableStdin: true,
          scrollback: 1000,
        });
        const fitAddon = new FitAddon();
        terminal.loadAddon(fitAddon);

        observed.set(sess.sessionId, { sessionId: sess.sessionId, label, terminal, fitAddon });

        wsAttach(sess.sessionId);
      }
    }

    // Update grid
    const { cols, rows } = getGridDimensions(observed.size);
    if (gridEl) {
      gridEl.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
      gridEl.style.gridTemplateRows = `repeat(${rows}, 1fr)`;
    }

    requestAnimationFrame(() => fitAll());
  }

  function openTerminalInCell(node: HTMLDivElement, obs: ObservedTerminal) {
    obs.terminal.open(node);
    requestAnimationFrame(() => obs.fitAddon.fit());
    return {
      destroy() {
        // Terminal cleanup handled in syncSessions/onDestroy
      },
    };
  }

  onMount(() => {
    syncSessions($sessions);

    unsubscribe = onWsMessage((msg) => {
      if (msg.type === "terminal:output") {
        const obs = observed.get(msg.sessionId);
        if (obs) obs.terminal.write(msg.data);
      }
      if (msg.type === "sessions:changed") {
        syncSessions(msg.sessions);
      }
    });

    resizeObserver = new ResizeObserver(() => fitAll());
    if (gridEl) resizeObserver.observe(gridEl);
  });

  onDestroy(() => {
    unsubscribe?.();
    resizeObserver?.disconnect();
    for (const obs of observed.values()) {
      obs.terminal.dispose();
    }
    observed.clear();
  });
</script>

<div class="observer-page">
  <div class="observer-header">
    <h1>Observer Mode</h1>
    <span class="observer-session-count">{$sessions.length} session(s)</span>
  </div>
  <div class="observer-grid" bind:this={gridEl}>
    {#each [...observed.values()] as obs (obs.sessionId)}
      <div class="observer-cell">
        <div class="observer-cell-header">
          <span class="observer-cell-label">
            <span class="status-dot open"></span>{obs.label}
          </span>
          <span class="observer-cell-detail">{obs.sessionId.slice(0, 8)}</span>
        </div>
        <div class="observer-cell-terminal" use:openTerminalInCell={obs}></div>
      </div>
    {/each}
    {#if $sessions.length === 0}
      <div class="observer-empty">
        <h2>No active sessions</h2>
        <p>
          Observer Mode shows a live read-only grid of every open session in your account &mdash;
          UI, MCP agent, and SSH-agent proxy connections all appear here side by side.
        </p>
        <p>Open a session from the sidebar or have an agent start one, and it will show up here.</p>
      </div>
    {/if}
  </div>
</div>

<style>
  .observer-page {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .observer-header {
    display: flex;
    align-items: center;
    gap: var(--space-5);
    padding: var(--space-4) var(--space-5);
    background: var(--surface-container-low);
    flex-shrink: 0;
  }

  .observer-header h1 {
    font-family: var(--font-display);
    font-size: var(--title-md);
    font-weight: 600;
    letter-spacing: -0.02em;
  }

  .observer-session-count {
    font-family: var(--font-mono);
    font-size: var(--label-sm);
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--on-surface-variant);
    flex: 1;
  }

  .observer-grid {
    flex: 1;
    display: grid;
    gap: var(--space-2);
    padding: var(--space-2);
    min-height: 0;
    background: var(--surface-dim);
  }

  .observer-cell {
    display: flex;
    flex-direction: column;
    background: var(--surface-container-highest);
    overflow: hidden;
    min-height: 0;
  }

  .observer-cell-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-2) var(--space-3);
    background: var(--surface-container-low);
    flex-shrink: 0;
  }

  .observer-cell-label {
    font-size: var(--label-md);
    font-weight: 600;
    display: flex;
    align-items: center;
    color: var(--on-surface);
  }

  .observer-cell-detail {
    font-size: var(--label-sm);
    color: var(--on-surface-variant);
    font-family: var(--font-mono);
  }

  .observer-cell-terminal {
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }

  .observer-cell-terminal :global(.xterm) {
    height: 100%;
    padding: 2px;
  }

  .observer-empty {
    grid-column: 1 / -1;
    grid-row: 1 / -1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--space-3);
    padding: var(--space-6);
    text-align: center;
    color: var(--on-surface-variant);
  }

  .observer-empty h2 {
    font-family: var(--font-display);
    font-size: var(--title-md);
    font-weight: 600;
    letter-spacing: -0.01em;
    color: var(--on-surface);
  }

  .observer-empty p {
    max-width: 56ch;
    line-height: 1.55;
    font-size: var(--body-md);
  }
</style>
