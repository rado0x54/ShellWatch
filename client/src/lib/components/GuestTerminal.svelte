<!-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0 -->
<script lang="ts">
  // xterm for the one-time access guest page (#306). Unlike Terminal.svelte it
  // knows nothing about the owner WebSocket store: input and size go to the
  // guest socket through the callbacks, output is written by the page.
  import { FitAddon } from "@xterm/addon-fit";
  import { Terminal } from "@xterm/xterm";
  import { onDestroy, onMount } from "svelte";

  interface Props {
    onInput: (data: string) => void;
    onResize: (cols: number, rows: number) => void;
  }

  let { onInput, onResize }: Props = $props();

  let containerEl: HTMLDivElement;
  let terminal: Terminal | null = null;
  let fitAddon: FitAddon | null = null;
  let resizeObserver: ResizeObserver | null = null;
  const pending: Array<{ data: string; reset: boolean }> = [];

  /** Write output; reset clears what was shown before (catch-up). */
  export function write(data: string, reset: boolean): void {
    if (!terminal) {
      pending.push({ data, reset });
      return;
    }
    if (reset) terminal.reset();
    terminal.write(data);
  }

  /** Print a local notice (not sent anywhere). */
  export function notice(text: string): void {
    terminal?.write(`\r\n\x1b[33m${text}\x1b[0m\r\n`);
  }

  onMount(() => {
    terminal = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "'Geist Mono', 'JetBrains Mono', ui-monospace, monospace",
      theme: {
        background: "#0e0e0e",
        foreground: "#f2f2f2",
        cursor: "#69f6b8",
        cursorAccent: "#002919",
        selectionBackground: "rgba(105, 246, 184, 0.25)",
      },
    });
    fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(containerEl);
    fitAddon.fit();
    terminal.onData((data) => onInput(data));
    for (const p of pending.splice(0)) write(p.data, p.reset);
    onResize(terminal.cols, terminal.rows);
    resizeObserver = new ResizeObserver(() => {
      if (fitAddon && terminal) {
        fitAddon.fit();
        onResize(terminal.cols, terminal.rows);
      }
    });
    resizeObserver.observe(containerEl);
    terminal.focus();
  });

  onDestroy(() => {
    resizeObserver?.disconnect();
    terminal?.dispose();
  });
</script>

<div class="guest-terminal" bind:this={containerEl}></div>

<style>
  .guest-terminal {
    height: 100%;
    width: 100%;
  }
</style>
