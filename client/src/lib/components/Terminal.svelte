<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
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
      fontFamily:
        "'Geist Mono', 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace",
      theme: {
        background: "#0e0e0e",
        foreground: "#f2f2f2",
        cursor: "#69f6b8",
        cursorAccent: "#002919",
        selectionBackground: "rgba(105, 246, 184, 0.25)",
        black: "#0e0e0e",
        red: "#ff5a5a",
        green: "#69f6b8",
        yellow: "#f8a010",
        blue: "#3fbe8a",
        magenta: "#b07a1a",
        cyan: "#69f6b8",
        white: "#adaaaa",
        brightBlack: "#494847",
        brightRed: "#ff5a5a",
        brightGreen: "#69f6b8",
        brightYellow: "#f8a010",
        brightBlue: "#3fbe8a",
        brightMagenta: "#b07a1a",
        brightCyan: "#69f6b8",
        brightWhite: "#f2f2f2",
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

    // Fresh xterm has no backlog — force full replay so a stale offset from a
    // previous mount (e.g. observer mode) doesn't cause an empty attach.
    wsAttach(sessionId, { fresh: true });
    wsSendResize(sessionId, terminal.cols, terminal.rows);

    unsubscribe = onWsMessage((msg) => {
      if (msg.type === "terminal:output" && msg.sessionId === sessionId) {
        if (msg.reset) terminal?.reset();
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
