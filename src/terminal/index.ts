// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
export { resolveKey, resolveKeys, SUPPORTED_KEYS } from "./keys.js";
export { OutputBuffer } from "./output-buffer.js";
export { TerminalManager, type TerminalManagerOptions } from "./terminal-manager.js";
export type { TerminalTransport, TransportFactory } from "./transport.js";
export {
  generateSessionId,
  type OutputReadResult,
  type TerminalEventMap,
  type TerminalSession,
  type TerminalSource,
  type TerminalStatus,
} from "./types.js";
