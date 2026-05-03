<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  import { FitAddon } from "@xterm/addon-fit";
  import { Terminal } from "@xterm/xterm";
  import { onDestroy, onMount } from "svelte";

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
      fontFamily:
        "'Geist Mono', 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace",
      rows,
      theme: {
        background: "#0e0e0e",
        foreground: "#f2f2f2",
        // 8-digit hex: fully transparent cursor — this is a read-only snapshot.
        cursor: "#00000000",
        selectionBackground: "rgba(105, 246, 184, 0.25)",
        green: "#69f6b8",
        yellow: "#f8a010",
        red: "#ff5a5a",
        brightGreen: "#69f6b8",
        brightYellow: "#f8a010",
        brightRed: "#ff5a5a",
        brightWhite: "#f2f2f2",
      },
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
