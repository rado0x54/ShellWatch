<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  // The one interactive terminal (#328). It knows no socket: the session page
  // passes the owner transport, the guest page the guest socket.
  import { FitAddon } from "@xterm/addon-fit";
  import { WebLinksAddon } from "@xterm/addon-web-links";
  import { Terminal } from "@xterm/xterm";
  import { onDestroy, onMount } from "svelte";
  import { TERMINAL_FONT_FAMILY, TERMINAL_THEME } from "$lib/terminal/theme.js";
  import {
    bindTerminal,
    type TerminalMode,
    type TerminalTransport,
  } from "$lib/terminal/transport.js";

  interface Props {
    transport: TerminalTransport;
    mode?: TerminalMode;
    fontSize?: number;
    readonly?: boolean;
    onModeChange?: (mode: TerminalMode) => void;
  }

  let {
    transport,
    mode = "control",
    fontSize = 14,
    readonly = false,
    onModeChange,
  }: Props = $props();

  let containerEl: HTMLDivElement;
  let terminal: Terminal | null = null;
  let resizeObserver: ResizeObserver | null = null;
  let unbind: (() => void) | null = null;

  onMount(() => {
    const term = new Terminal({
      cursorBlink: !readonly,
      fontSize,
      fontFamily: TERMINAL_FONT_FAMILY,
      theme: TERMINAL_THEME,
      disableStdin: readonly || mode === "observer",
    });
    terminal = term;
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(new WebLinksAddon());
    term.open(containerEl);
    fitAddon.fit();

    if (!readonly) term.onData((data) => transport.sendInput(data));
    unbind = bindTerminal(
      {
        reset: () => term.reset(),
        write: (data) => term.write(data),
        setInputEnabled: (on) => (term.options.disableStdin = readonly || !on),
      },
      transport,
      (m) => {
        mode = m;
        onModeChange?.(m);
      },
    );
    transport.sendResize(term.cols, term.rows);

    resizeObserver = new ResizeObserver(() => {
      fitAddon.fit();
      transport.sendResize(term.cols, term.rows);
    });
    resizeObserver.observe(containerEl);
    term.focus();
  });

  onDestroy(() => {
    unbind?.();
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
