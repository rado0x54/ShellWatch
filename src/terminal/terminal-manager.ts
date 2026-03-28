import { EventEmitter } from "node:events";
import type { Config } from "../config/index.js";
import { resolveKeys } from "./keys.js";
import { OutputBuffer } from "./output-buffer.js";
import type { TerminalTransport, TransportFactory } from "./transport.js";
import {
  type ExecResult,
  generateSessionId,
  type OutputReadResult,
  type TerminalEventMap,
  type TerminalSession,
  type TerminalSource,
  type TerminalStatus,
} from "./types.js";

interface ManagedTerminal {
  session: TerminalSession;
  transport: TerminalTransport;
  output: OutputBuffer;
}

export interface TerminalManagerOptions {
  idleTimeoutMs?: number;
  cleanupIntervalMs?: number;
  maxOutputBufferSize?: number;
}

const DEFAULT_IDLE_TIMEOUT = 30 * 60 * 1000; // 30 minutes
const DEFAULT_CLEANUP_INTERVAL = 60 * 1000; // 1 minute

export class TerminalManager extends EventEmitter<TerminalEventMap> {
  private terminals = new Map<string, ManagedTerminal>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private idleTimeoutMs: number;
  private maxOutputBufferSize: number | undefined;

  constructor(
    private config: Config,
    private transportFactory: TransportFactory,
    options: TerminalManagerOptions = {},
  ) {
    super();
    this.idleTimeoutMs = options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT;
    this.maxOutputBufferSize = options.maxOutputBufferSize;

    const cleanupInterval = options.cleanupIntervalMs ?? DEFAULT_CLEANUP_INTERVAL;
    this.cleanupTimer = setInterval(() => this.cleanupIdleTerminals(), cleanupInterval);
    this.cleanupTimer.unref();
  }

  async create(endpointId: string, source: TerminalSource): Promise<TerminalSession> {
    const endpoint = this.config.servers.find((s) => s.id === endpointId);
    if (!endpoint) {
      throw new Error(`Unknown endpoint: ${endpointId}`);
    }

    const sessionId = generateSessionId();
    const now = new Date();

    const session: TerminalSession = {
      sessionId,
      endpointId,
      status: "opening",
      createdAt: now,
      lastActivityAt: now,
      source,
    };

    const output = new OutputBuffer(this.maxOutputBufferSize);

    let transport: TerminalTransport;
    try {
      transport = await this.transportFactory(endpointId);
    } catch (err) {
      session.status = "error";
      throw new Error(`Failed to connect to ${endpointId}: ${(err as Error).message}`);
    }

    const managed: ManagedTerminal = { session, transport, output };
    this.terminals.set(sessionId, managed);

    transport.on("data", (data: string) => {
      output.append(data);
      managed.session.lastActivityAt = new Date();
      this.emit("output", { sessionId, data });
    });

    transport.on("close", () => {
      this.setStatus(managed, "closed");
    });

    transport.on("error", () => {
      this.setStatus(managed, "error");
    });

    this.setStatus(managed, "open");
    return { ...session, status: "open" };
  }

  sendInput(sessionId: string, input: string): void {
    const managed = this.getManaged(sessionId);
    if (managed.session.status !== "open") {
      throw new Error(`Terminal ${sessionId} is not open (status: ${managed.session.status})`);
    }
    managed.transport.write(input);
    managed.session.lastActivityAt = new Date();
  }

  sendKeys(sessionId: string, keys: string[]): void {
    const managed = this.getManaged(sessionId);
    if (managed.session.status !== "open") {
      throw new Error(`Terminal ${sessionId} is not open (status: ${managed.session.status})`);
    }
    const data = resolveKeys(keys);
    managed.transport.write(data);
    managed.session.lastActivityAt = new Date();
  }

  async exec(sessionId: string, command: string, timeout = 30000): Promise<ExecResult> {
    const managed = this.getManaged(sessionId);
    if (managed.session.status !== "open") {
      throw new Error(`Terminal ${sessionId} is not open (status: ${managed.session.status})`);
    }

    const id = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const startMarker = `__SW_START_${id}__`;
    const endMarker = `__SW_END_${id}__`;

    // Use echo with start/end markers so we capture only the command output,
    // not the echoed command line or PTY control characters
    const wrappedCommand = `echo "${startMarker}"; ${command}; echo "${endMarker}_EXIT_$?"`;

    const startOffset = managed.output.currentOffset;
    const startTime = Date.now();

    managed.transport.write(`${wrappedCommand}\n`);
    managed.session.lastActivityAt = new Date();

    return new Promise<ExecResult>((resolve) => {
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        cleanup();
        const partial = managed.output.read(startOffset);
        resolve({
          output: partial.data,
          exitCode: -1,
          durationMs: Date.now() - startTime,
          timedOut: true,
        });
      }, timeout);

      const onOutput = ({ sessionId: sid }: { sessionId: string }) => {
        if (sid !== sessionId || timedOut) return;

        const result = managed.output.read(startOffset);

        // Both markers appear twice in the buffer: once in the echoed command line,
        // once as actual shell output. We need the OUTPUT versions.
        // Use regex to handle \r\n, \n, or \r line endings from real terminals.
        const startRegex = new RegExp(
          `\\r?\\n${startMarker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\r?\\n`,
        );
        const startMatch = startRegex.exec(result.data);
        if (!startMatch) return;

        const outputStart = startMatch.index + startMatch[0].length;

        // Find the end marker AFTER the start marker output
        const endPrefix = `${endMarker}_EXIT_`;
        const endIdx = result.data.indexOf(endPrefix, outputStart);
        if (endIdx === -1) return;

        cleanup();

        // Parse exit code from end marker
        const afterEnd = result.data.slice(endIdx + endPrefix.length);
        const exitCodeStr = afterEnd.split(/\s/)[0];
        const exitCode = parseInt(exitCodeStr, 10) || 0;

        // Strip any trailing \r characters from output lines
        const output = result.data.slice(outputStart, endIdx).replace(/\r/g, "").trimEnd();

        resolve({
          output,
          exitCode,
          durationMs: Date.now() - startTime,
          timedOut: false,
        });
      };

      const cleanup = () => {
        clearTimeout(timer);
        this.off("output", onOutput);
      };

      this.on("output", onOutput);
    });
  }

  readOutput(sessionId: string, afterOffset?: number, limit?: number): OutputReadResult {
    const managed = this.getManaged(sessionId);
    return managed.output.read(afterOffset, limit);
  }

  resize(sessionId: string, cols: number, rows: number): void {
    const managed = this.getManaged(sessionId);
    if (managed.session.status !== "open") {
      throw new Error(`Terminal ${sessionId} is not open (status: ${managed.session.status})`);
    }
    managed.transport.resize(cols, rows);
  }

  listSessions(): TerminalSession[] {
    return Array.from(this.terminals.values())
      .filter((m) => m.session.status !== "closed")
      .map((m) => ({ ...m.session }));
  }

  getSession(sessionId: string): TerminalSession | null {
    const managed = this.terminals.get(sessionId);
    return managed ? { ...managed.session } : null;
  }

  close(sessionId: string): void {
    const managed = this.getManaged(sessionId);
    if (managed.session.status === "closed" || managed.session.status === "closing") {
      return;
    }
    this.setStatus(managed, "closing");
    managed.transport.close();
    managed.output.clear();
    this.setStatus(managed, "closed");
    this.terminals.delete(sessionId);
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    for (const sessionId of this.terminals.keys()) {
      this.close(sessionId);
    }
  }

  private getManaged(sessionId: string): ManagedTerminal {
    const managed = this.terminals.get(sessionId);
    if (!managed) {
      throw new Error(`Terminal session not found: ${sessionId}`);
    }
    return managed;
  }

  private setStatus(managed: ManagedTerminal, status: TerminalStatus): void {
    const previousStatus = managed.session.status;
    if (previousStatus === status) return;
    managed.session.status = status;
    this.emit("status-change", {
      sessionId: managed.session.sessionId,
      status,
      previousStatus,
    });
    if (status === "closed") {
      this.emit("close", { sessionId: managed.session.sessionId });
    }
  }

  private cleanupIdleTerminals(): void {
    const now = Date.now();
    for (const [sessionId, managed] of this.terminals) {
      if (managed.session.status !== "open") continue;
      const idle = now - managed.session.lastActivityAt.getTime();
      if (idle > this.idleTimeoutMs) {
        this.close(sessionId);
      }
    }
  }
}
