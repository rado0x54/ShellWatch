/**
 * Marker-based command execution for terminal sessions.
 *
 * CURRENTLY DISABLED — the dual-marker approach works but is brittle with real PTYs
 * due to terminal echo, \r\n handling, line wrapping, and shell-specific behavior.
 *
 * The current preferred approach is for agents to use send_keys + read_output directly,
 * which gives them full control over timing and avoids marker injection.
 *
 * This module is preserved for future use — it could be re-enabled with improvements:
 * - Better marker detection (e.g., using ANSI OSC sequences)
 * - Shell-specific adapters (bash vs zsh vs fish)
 * - Non-PTY execution mode (ssh2 exec channel instead of shell)
 */

import type { EventEmitter } from "node:events";
import type { OutputBuffer } from "./output-buffer.js";
import type { TerminalTransport } from "./transport.js";
import type { ExecResult, TerminalEventMap } from "./types.js";

interface ExecContext {
  sessionId: string;
  transport: TerminalTransport;
  output: OutputBuffer;
  emitter: EventEmitter<TerminalEventMap>;
}

export async function execCommand(
  ctx: ExecContext,
  command: string,
  timeout = 30000,
): Promise<ExecResult> {
  const id = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const startMarker = `__SW_START_${id}__`;
  const endMarker = `__SW_END_${id}__`;

  const wrappedCommand = `echo "${startMarker}"; ${command}; echo "${endMarker}_EXIT_$?"`;

  const startOffset = ctx.output.currentOffset;
  const startTime = Date.now();

  ctx.transport.write(`${wrappedCommand}\n`);

  return new Promise<ExecResult>((resolve) => {
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      cleanup();
      const partial = ctx.output.read(startOffset);
      resolve({
        output: partial.data,
        exitCode: -1,
        durationMs: Date.now() - startTime,
        timedOut: true,
      });
    }, timeout);

    const onOutput = ({ sessionId: sid }: { sessionId: string }) => {
      if (sid !== ctx.sessionId || timedOut) return;

      const result = ctx.output.read(startOffset);

      // Use regex to handle \r\n, \n, or \r line endings from real terminals.
      const startRegex = new RegExp(
        `\\r?\\n${startMarker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\r?\\n`,
      );
      const startMatch = startRegex.exec(result.data);
      if (!startMatch) return;

      const outputStart = startMatch.index + startMatch[0].length;

      const endPrefix = `${endMarker}_EXIT_`;
      const endIdx = result.data.indexOf(endPrefix, outputStart);
      if (endIdx === -1) return;

      cleanup();

      const afterEnd = result.data.slice(endIdx + endPrefix.length);
      const exitCodeStr = afterEnd.split(/\s/)[0];
      const exitCode = parseInt(exitCodeStr, 10) || 0;

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
      ctx.emitter.off("output", onOutput);
    };

    ctx.emitter.on("output", onOutput);
  });
}
