import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { Terminal } from "@xterm/xterm";
import type { WsClient } from "./ws-client.js";

interface ManagedTerminal {
  terminal: Terminal;
  fitAddon: FitAddon;
  element: HTMLDivElement;
}

export class TerminalView {
  private terminals = new Map<string, ManagedTerminal>();
  private activeSessionId: string | null = null;
  private resizeObserver: ResizeObserver | null = null;

  constructor(private wsClient: WsClient) {
    // Single message handler — routes output to the correct terminal
    this.wsClient.onMessage((msg) => {
      if (msg.type === "terminal:output") {
        const managed = this.terminals.get(msg.sessionId);
        if (managed) managed.terminal.write(msg.data);
      }
      if (msg.type === "terminal:closed") {
        const managed = this.terminals.get(msg.sessionId);
        if (managed) {
          managed.terminal.write("\r\n\x1b[31m[Session closed]\x1b[0m\r\n");
        }
      }
    });
  }

  attach(sessionId: string, container: HTMLElement): void {
    // Hide all existing terminal elements
    for (const managed of this.terminals.values()) {
      managed.element.style.display = "none";
    }

    // Hide placeholder
    const placeholder = document.getElementById("terminal-placeholder");
    if (placeholder) placeholder.style.display = "none";

    let managed = this.terminals.get(sessionId);

    if (!managed) {
      // Create a new terminal for this session
      const terminal = new Terminal({
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

      const fitAddon = new FitAddon();
      terminal.loadAddon(fitAddon);
      terminal.loadAddon(new WebLinksAddon());

      const element = document.createElement("div");
      element.style.height = "100%";
      container.appendChild(element);

      terminal.open(element);
      fitAddon.fit();

      // Wire input for this terminal
      terminal.onData((data) => {
        this.wsClient.sendInput(sessionId, data);
      });

      managed = { terminal, fitAddon, element };
      this.terminals.set(sessionId, managed);

      // Attach to WS and send initial resize
      this.wsClient.attach(sessionId);
      this.wsClient.sendResize(sessionId, terminal.cols, terminal.rows);
    }

    // Show this terminal
    managed.element.style.display = "block";
    managed.fitAddon.fit();
    managed.terminal.focus();
    this.activeSessionId = sessionId;

    // Resize observer — refit the active terminal
    if (this.resizeObserver) this.resizeObserver.disconnect();
    this.resizeObserver = new ResizeObserver(() => {
      if (this.activeSessionId) {
        const active = this.terminals.get(this.activeSessionId);
        if (active) {
          active.fitAddon.fit();
          this.wsClient.sendResize(
            this.activeSessionId,
            active.terminal.cols,
            active.terminal.rows,
          );
        }
      }
    });
    this.resizeObserver.observe(container);
  }

  detach(): void {
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
      this.resizeObserver = null;
    }
    this.activeSessionId = null;
  }

  removeSession(sessionId: string): void {
    const managed = this.terminals.get(sessionId);
    if (managed) {
      managed.terminal.dispose();
      managed.element.remove();
      this.terminals.delete(sessionId);
    }
    if (this.activeSessionId === sessionId) {
      this.activeSessionId = null;
    }
  }

  getActiveSessionId(): string | null {
    return this.activeSessionId;
  }
}
