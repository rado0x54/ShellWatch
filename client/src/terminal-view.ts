import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { Terminal } from "@xterm/xterm";
import type { SessionMode, WsClient } from "./ws-client.js";

interface ManagedTerminal {
  terminal: Terminal;
  fitAddon: FitAddon;
  element: HTMLDivElement;
  mode: SessionMode;
  inputDisposable: { dispose: () => void } | null;
}

export class TerminalView {
  private terminals = new Map<string, ManagedTerminal>();
  private activeSessionId: string | null = null;
  private resizeObserver: ResizeObserver | null = null;
  private onModeChange: ((sessionId: string, mode: SessionMode) => void) | null = null;

  constructor(private wsClient: WsClient) {
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
      if (msg.type === "terminal:mode") {
        const managed = this.terminals.get(msg.sessionId);
        if (managed) {
          this.setMode(msg.sessionId, managed, msg.mode);
        }
      }
    });
  }

  setModeChangeCallback(cb: (sessionId: string, mode: SessionMode) => void): void {
    this.onModeChange = cb;
  }

  attach(sessionId: string, container: HTMLElement, initialMode: SessionMode = "control"): void {
    for (const managed of this.terminals.values()) {
      managed.element.style.display = "none";
    }

    const placeholder = document.getElementById("terminal-placeholder");
    if (placeholder) placeholder.style.display = "none";

    let managed = this.terminals.get(sessionId);

    if (!managed) {
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
        disableStdin: initialMode === "observer",
      });

      const fitAddon = new FitAddon();
      terminal.loadAddon(fitAddon);
      terminal.loadAddon(new WebLinksAddon());

      const element = document.createElement("div");
      element.style.height = "100%";
      container.appendChild(element);

      terminal.open(element);
      fitAddon.fit();

      // Wire input — only sends if mode is control (checked server-side too)
      const inputDisposable = terminal.onData((data) => {
        this.wsClient.sendInput(sessionId, data);
      });

      managed = { terminal, fitAddon, element, mode: initialMode, inputDisposable };
      this.terminals.set(sessionId, managed);
      this.updateBorder(managed);

      this.wsClient.attach(sessionId);
      this.wsClient.sendResize(sessionId, terminal.cols, terminal.rows);
    }

    managed.element.style.display = "block";
    managed.fitAddon.fit();
    managed.terminal.focus();
    this.activeSessionId = sessionId;

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

  getMode(sessionId: string): SessionMode | null {
    return this.terminals.get(sessionId)?.mode ?? null;
  }

  private setMode(sessionId: string, managed: ManagedTerminal, mode: SessionMode): void {
    managed.mode = mode;
    managed.terminal.options.disableStdin = mode === "observer";
    this.updateBorder(managed);
    this.onModeChange?.(sessionId, mode);
  }

  private updateBorder(managed: ManagedTerminal): void {
    managed.element.classList.toggle("terminal-observer", managed.mode === "observer");
    managed.element.classList.toggle("terminal-control", managed.mode === "control");
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
      managed.inputDisposable?.dispose();
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
