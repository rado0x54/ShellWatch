import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import type { SessionListEntry, WsClient } from "./ws-client.js";

interface ObservedTerminal {
  sessionId: string;
  label: string;
  terminal: Terminal;
  fitAddon: FitAddon;
  cell: HTMLDivElement;
}

/**
 * Observer mode: shows all active sessions simultaneously in a dynamic grid.
 *
 * Layout adapts to session count:
 * 1 → full, 2 → 1x2, 3-4 → 2x2, 5-6 → 2x3, 7-9 → 3x3, 10-12 → 3x4, 13-16 → 4x4
 */
export class ObserverPage {
  private container: HTMLElement;
  private grid: HTMLDivElement | null = null;
  private terminals = new Map<string, ObservedTerminal>();
  private visible = false;
  private resizeObserver: ResizeObserver | null = null;
  private unsubscribe: (() => void) | null = null;
  private onClose: () => void;
  private wsClient: WsClient;
  private endpointLabels = new Map<string, string>();

  constructor(container: HTMLElement, wsClient: WsClient, onClose: () => void) {
    this.container = container;
    this.wsClient = wsClient;
    this.onClose = onClose;
  }

  setEndpoints(endpoints: Array<{ id: string; label: string }>): void {
    this.endpointLabels.clear();
    for (const ep of endpoints) {
      this.endpointLabels.set(ep.id, ep.label);
    }
  }

  show(sessions: SessionListEntry[]): void {
    this.visible = true;
    this.container.style.display = "block";

    this.container.innerHTML = `
      <div class="observer-page">
        <div class="observer-header">
          <h1>Observer Mode</h1>
          <span class="observer-session-count">${sessions.length} session(s)</span>
          <button type="button" class="btn btn-close" id="observer-close">Back</button>
        </div>
        <div class="observer-grid" id="observer-grid"></div>
      </div>
    `;

    this.grid = document.getElementById("observer-grid") as HTMLDivElement;

    this.container.querySelector("#observer-close")?.addEventListener("click", () => {
      this.hide();
      this.onClose();
    });

    // Subscribe to terminal output
    this.unsubscribe = this.wsClient.onMessage((msg) => {
      if (msg.type === "terminal:output") {
        const obs = this.terminals.get(msg.sessionId);
        if (obs) obs.terminal.write(msg.data);
      }
    });

    // Build terminals for current sessions
    this.syncSessions(sessions);

    // Observe container resize to refit terminals
    this.resizeObserver = new ResizeObserver(() => this.fitAll());
    this.resizeObserver.observe(this.grid);
  }

  hide(): void {
    this.visible = false;
    this.container.style.display = "none";

    // Clean up terminals
    for (const obs of this.terminals.values()) {
      obs.terminal.dispose();
      obs.cell.remove();
    }
    this.terminals.clear();

    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
      this.resizeObserver = null;
    }

    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }

    this.container.innerHTML = "";
    this.grid = null;
  }

  isVisible(): boolean {
    return this.visible;
  }

  /** Update the grid when sessions change. */
  updateSessions(sessions: SessionListEntry[]): void {
    if (!this.visible) return;

    // Update session count
    const countEl = this.container.querySelector(".observer-session-count");
    if (countEl) countEl.textContent = `${sessions.length} session(s)`;

    this.syncSessions(sessions);
  }

  private syncSessions(sessions: SessionListEntry[]): void {
    if (!this.grid) return;

    const currentIds = new Set(this.terminals.keys());
    const newIds = new Set(sessions.map((s) => s.sessionId));

    // Remove terminals for closed sessions
    for (const id of currentIds) {
      if (!newIds.has(id)) {
        const obs = this.terminals.get(id)!;
        obs.terminal.dispose();
        obs.cell.remove();
        this.terminals.delete(id);
      }
    }

    // Add terminals for new sessions
    for (const sess of sessions) {
      if (!this.terminals.has(sess.sessionId)) {
        this.addTerminal(sess);
      }
    }

    // Update grid layout
    this.updateGridLayout();
    // Fit after layout change
    requestAnimationFrame(() => this.fitAll());
  }

  private addTerminal(sess: SessionListEntry): void {
    if (!this.grid) return;

    const label = this.endpointLabels.get(sess.endpointId) ?? sess.endpointId;

    const cell = document.createElement("div");
    cell.className = "observer-cell";
    cell.innerHTML = `
      <div class="observer-cell-header">
        <span class="observer-cell-label">
          <span class="status-dot ${sess.status}"></span>${label}
        </span>
        <span class="observer-cell-detail">${sess.sessionId.slice(0, 8)}</span>
      </div>
      <div class="observer-cell-terminal"></div>
    `;

    const termContainer = cell.querySelector(".observer-cell-terminal") as HTMLDivElement;

    const terminal = new Terminal({
      cursorBlink: false,
      fontSize: 11,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      theme: {
        background: "#1a1a2e",
        foreground: "#e0e0e0",
        cursor: "#4a9eff",
        selectionBackground: "#4a9eff44",
      },
      disableStdin: true,
      scrollback: 1000,
    });

    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);

    this.grid.appendChild(cell);
    terminal.open(termContainer);

    // Attach as observer to receive output
    this.wsClient.attach(sess.sessionId);

    const obs: ObservedTerminal = { sessionId: sess.sessionId, label, terminal, fitAddon, cell };
    this.terminals.set(sess.sessionId, obs);
  }

  private updateGridLayout(): void {
    if (!this.grid) return;
    const count = this.terminals.size;
    const { cols, rows } = this.getGridDimensions(count);
    this.grid.style.gridTemplateColumns = `repeat(${cols}, 1fr)`;
    this.grid.style.gridTemplateRows = `repeat(${rows}, 1fr)`;
  }

  private getGridDimensions(count: number): { cols: number; rows: number } {
    if (count <= 1) return { cols: 1, rows: 1 };
    if (count <= 2) return { cols: 2, rows: 1 };
    if (count <= 4) return { cols: 2, rows: 2 };
    if (count <= 6) return { cols: 3, rows: 2 };
    if (count <= 9) return { cols: 3, rows: 3 };
    if (count <= 12) return { cols: 4, rows: 3 };
    return { cols: 4, rows: 4 };
  }

  private fitAll(): void {
    for (const obs of this.terminals.values()) {
      try {
        obs.fitAddon.fit();
      } catch {
        // Terminal may not be fully rendered yet
      }
    }
  }
}
