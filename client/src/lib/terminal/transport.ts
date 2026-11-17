// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * What Terminal.svelte talks to (#328): the owner socket for a session page,
 * the guest socket on `/t`. Both carry the same terminal frames; the
 * transport hides which socket and which session id.
 */

export type TerminalMode = "control" | "observer";

/** Where a transport delivers one session's frames. */
export interface TerminalSink {
  /** Output; `reset` clears what was shown first (catch-up). */
  output(data: string, reset: boolean): void;
  closed(): void;
  mode?(mode: TerminalMode): void;
}

export interface TerminalTransport {
  /** Start delivering frames to `sink`; the result stops it. */
  subscribe(sink: TerminalSink): () => void;
  sendInput(data: string): void;
  sendResize(cols: number, rows: number): void;
}

/** The part of an xterm instance `bindTerminal` drives. */
export interface TerminalView {
  reset(): void;
  write(data: string): void;
  setInputEnabled(enabled: boolean): void;
}

export const SESSION_CLOSED_BANNER = "\r\n\x1b[31m[Session closed]\x1b[0m\r\n";

/** Wire a view to a transport: output and mode in; returns the unbind. Input
 * and resize go out through the transport directly. */
export function bindTerminal(
  view: TerminalView,
  transport: TerminalTransport,
  onModeChange?: (mode: TerminalMode) => void,
): () => void {
  return transport.subscribe({
    output(data, reset) {
      if (reset) view.reset();
      view.write(data);
    },
    closed() {
      view.write(SESSION_CLOSED_BANNER);
    },
    mode(mode) {
      view.setInputEnabled(mode === "control");
      onModeChange?.(mode);
    },
  });
}
