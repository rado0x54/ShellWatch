import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { Terminal } from "@xterm/xterm";
import type { WsClient } from "./ws-client.js";

export class TerminalView {
  private terminal: Terminal;
  private fitAddon: FitAddon;
  private sessionId: string | null = null;
  private resizeObserver: ResizeObserver | null = null;
  private unsubscribe: (() => void) | null = null;

  constructor(private wsClient: WsClient) {
    this.terminal = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      theme: {
        background: "#1a1a2e",
        foreground: "#e0e0e0",
        cursor: "#4a9eff",
        selectionBackground: "#4a9eff44",
      },
    });

    this.fitAddon = new FitAddon();
    this.terminal.loadAddon(this.fitAddon);
    this.terminal.loadAddon(new WebLinksAddon());
  }

  attach(sessionId: string, container: HTMLElement): void {
    this.detach();
    this.sessionId = sessionId;

    // Clear container and mount terminal
    container.innerHTML = "";
    const placeholder = document.getElementById("terminal-placeholder");
    if (placeholder) placeholder.style.display = "none";

    this.terminal.open(container);
    this.fitAddon.fit();

    // Wire input
    this.terminal.onData((data) => {
      this.wsClient.sendInput(sessionId, data);
    });

    // Wire resize
    this.resizeObserver = new ResizeObserver(() => {
      this.fitAddon.fit();
      const { cols, rows } = this.terminal;
      this.wsClient.sendResize(sessionId, cols, rows);
    });
    this.resizeObserver.observe(container);

    // Wire output from server
    this.unsubscribe = this.wsClient.onMessage((msg) => {
      if (msg.type === "terminal:output" && msg.sessionId === sessionId) {
        this.terminal.write(msg.data);
      }
      if (msg.type === "terminal:closed" && msg.sessionId === sessionId) {
        this.terminal.write("\r\n\x1b[31m[Session closed]\x1b[0m\r\n");
      }
    });

    // Attach to WS
    this.wsClient.attach(sessionId);

    // Send initial resize
    const { cols, rows } = this.terminal;
    this.wsClient.sendResize(sessionId, cols, rows);

    this.terminal.focus();
  }

  detach(): void {
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
      this.resizeObserver = null;
    }
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
    this.sessionId = null;
  }

  getActiveSessionId(): string | null {
    return this.sessionId;
  }
}
