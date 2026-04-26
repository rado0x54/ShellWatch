import { EventEmitter } from "node:events";

// App-level event bus for account-state changes that need cleanup outside the
// DB. The DELETE /api/accounts/:id route emits `deleted` after the row cascade
// completes; subscribers (TerminalManager teardown, MCP transport map, future
// per-account caches) react synchronously. Keeping this in one place avoids
// adding ad-hoc cross-references between routes and long-lived in-memory
// stores. See #122 / #134.

export interface AccountDeletedEvent {
  accountId: string;
}

interface AccountLifecycleEvents {
  deleted: [AccountDeletedEvent];
}

export class AccountLifecycle extends EventEmitter<AccountLifecycleEvents> {
  emitDeleted(accountId: string): void {
    this.emit("deleted", { accountId });
  }
}
