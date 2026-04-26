import type { EventEmitter } from "node:events";

/**
 * Abstract transport interface for a terminal's underlying connection.
 * Implemented by SSH transport (issue #3), and potentially other
 * transports (local shell, docker exec, etc.) in the future.
 */
export interface TerminalTransport extends EventEmitter {
  /** Send raw input to the remote shell */
  write(data: string): void;
  /** Resize the remote PTY */
  resize(cols: number, rows: number): void;
  /** Close the connection and release resources */
  close(): void;
}

import type { EndpointInfo } from "../db/repositories/endpoint-repo.js";
import type { EndpointAuthTrigger } from "../pending-action/types.js";

export interface TransportFactoryParams {
  endpoint: EndpointInfo;
  sessionId: string;
  trigger: EndpointAuthTrigger;
}

export type TransportFactory = (params: TransportFactoryParams) => Promise<TerminalTransport>;
