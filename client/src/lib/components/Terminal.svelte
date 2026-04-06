<script lang="ts">
  import { FitAddon } from "@xterm/addon-fit";
  import { WebLinksAddon } from "@xterm/addon-web-links";
  import { Terminal } from "@xterm/xterm";
  import { onDestroy, onMount } from "svelte";
  import {
    onWsMessage,
    type SessionMode,
    wsAttach,
    wsDetach,
    wsSendInput,
    wsSendResize,
  } from "$lib/stores/ws.js";

  interface Props {
    sessionId: string;
    mode?: SessionMode;
    fontSize?: number;
    readonly?: boolean;
    onModeChange?: (mode: SessionMode) => void;
  }

  let {
    sessionId,
    mode = "control",
    fontSize = 14,
    readonly = false,
    onModeChange,
  }: Props = $props();

  let containerEl: HTMLDivElement;
  let terminal: Terminal | null = null;
  let fitAddon: FitAddon | null = null;
  let resizeObserver: ResizeObserver | null = null;
  let unsubscribe: (() => void) | null = null;

  onMount(() => {
    terminal = new Terminal({
      cursorBlink: !readonly,
      fontSize,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      theme: {
        background: "#1a1a2e",
        foreground: "#e0e0e0",
        cursor: "#4a9eff",
        selectionBackground: "#4a9eff44",
      },
      disableStdin: readonly || mode === "observer",
    });

    fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.loadAddon(new WebLinksAddon());

    terminal.open(containerEl);
    fitAddon.fit();

    if (!readonly) {
      terminal.onData((data) => {
        wsSendInput(sessionId, data);
      });
    }

    wsAttach(sessionId);
    wsSendResize(sessionId, terminal.cols, terminal.rows);

    unsubscribe = onWsMessage((msg) => {
      if (msg.type === "terminal:output" && msg.sessionId === sessionId) {
        terminal?.write(msg.data);
      }
      if (msg.type === "terminal:closed" && msg.sessionId === sessionId) {
        terminal?.write("\r\n\x1b[31m[Session closed]\x1b[0m\r\n");
      }
      if (msg.type === "terminal:mode" && msg.sessionId === sessionId) {
        mode = msg.mode;
        if (terminal) {
          terminal.options.disableStdin = msg.mode === "observer";
        }
        onModeChange?.(msg.mode);
      }
    });

    resizeObserver = new ResizeObserver(() => {
      if (fitAddon && terminal) {
        fitAddon.fit();
        wsSendResize(sessionId, terminal.cols, terminal.rows);
      }
    });
    resizeObserver.observe(containerEl);

    terminal.focus();
  });

  onDestroy(() => {
    wsDetach(sessionId);
    unsubscribe?.();
    resizeObserver?.disconnect();
    terminal?.dispose();
  });
</script>

<div
  class="terminal-wrapper"
  class:terminal-observer={mode === "observer"}
  class:terminal-control={mode === "control"}
  bind:this={containerEl}
></div>

<style>
  .terminal-wrapper {
    height: 100%;
    width: 100%;
  }
</style>
