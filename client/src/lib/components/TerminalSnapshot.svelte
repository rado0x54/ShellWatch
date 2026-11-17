<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { FitAddon } from "@xterm/addon-fit";
  import { Terminal } from "@xterm/xterm";
  import { onDestroy, onMount } from "svelte";
  import { READONLY_TERMINAL_THEME, TERMINAL_FONT_FAMILY } from "$lib/terminal/theme.js";

  interface Props {
    data: string;
    rows?: number;
    fontSize?: number;
  }

  let { data, rows = 12, fontSize = 12 }: Props = $props();

  let containerEl: HTMLDivElement;
  let terminal: Terminal | null = null;
  let fitAddon: FitAddon | null = null;
  let resizeObserver: ResizeObserver | null = null;

  onMount(() => {
    terminal = new Terminal({
      cursorBlink: false,
      disableStdin: true,
      scrollback: 5000,
      fontSize,
      fontFamily: TERMINAL_FONT_FAMILY,
      rows,
      // Fully transparent cursor: this is a read-only snapshot.
      theme: READONLY_TERMINAL_THEME,
    });

    fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(containerEl);
    fitAddon.fit();

    resizeObserver = new ResizeObserver(() => {
      if (fitAddon) fitAddon.fit();
    });
    resizeObserver.observe(containerEl);
  });

  // Re-render whenever `data` changes. reset() clears the screen and parser
  // state so successive updates don't append or inherit escape-sequence state
  // from the previous snapshot.
  $effect(() => {
    if (!terminal) return;
    terminal.reset();
    terminal.write(data);
  });

  onDestroy(() => {
    resizeObserver?.disconnect();
    terminal?.dispose();
  });
</script>

<div class="snapshot-wrapper" bind:this={containerEl}></div>

<style>
  .snapshot-wrapper {
    width: 100%;
    height: 100%;
  }
</style>
