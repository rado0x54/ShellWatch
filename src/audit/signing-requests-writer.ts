import type {
  PendingAction,
  PendingActionResolvedEvent,
  PendingActionStore,
  SignRequestContext,
} from "../pending-action/index.js";
import type { SigningRequestInsert, SigningRequestsRepository } from "./signing-requests-repo.js";

export interface SigningRequestsWriterDeps {
  actionStore: PendingActionStore;
  repo: SigningRequestsRepository;
  /** Optional logger; defaults to no-op so this module is easy to drop in. */
  log?: { error(err: unknown, msg: string): void };
}

/**
 * Subscribes to PendingActionStore transitions and writes audit rows.
 *
 *   "created"  -> INSERT a row representing the in-flight signing request
 *   "resolved" -> UPDATE the row with outcome, resolved_at, latency_ms, cancel_reason
 *
 * Lifecycle is single-shot: created at app start, kept alive for the process
 * lifetime. dispose() detaches listeners (used by tests).
 *
 * Audit-write failures are swallowed — observability must not turn into an
 * availability incident on the live signing path.
 */
export class SigningRequestsWriter {
  private readonly createdListener: (action: PendingAction) => void;
  private readonly resolvedListener: (event: PendingActionResolvedEvent) => void;

  constructor(private deps: SigningRequestsWriterDeps) {
    this.createdListener = (action) => this.handleCreated(action);
    this.resolvedListener = (event) => this.handleResolved(event);
    this.deps.actionStore.on("created", this.createdListener);
    this.deps.actionStore.on("resolved", this.resolvedListener);
  }

  dispose(): void {
    this.deps.actionStore.off("created", this.createdListener);
    this.deps.actionStore.off("resolved", this.resolvedListener);
  }

  private handleCreated(action: PendingAction): void {
    try {
      this.deps.repo.insertCreated(toInsert(action));
    } catch (err) {
      this.deps.log?.error(err, `Failed to record signing request created for ${action.id}`);
    }
  }

  private handleResolved(event: PendingActionResolvedEvent): void {
    const { action, outcome, resolvedAt, cancelReason } = event;
    try {
      this.deps.repo.recordResolution({
        id: action.id,
        outcome,
        resolvedAt: new Date(resolvedAt).toISOString(),
        latencyMs: resolvedAt - action.createdAt,
        cancelReason,
      });
    } catch (err) {
      this.deps.log?.error(err, `Failed to record signing request resolution for ${action.id}`);
    }
  }
}

function toInsert(action: PendingAction): SigningRequestInsert {
  const ctxFields = mapContext(action.context);
  const typeFields =
    action.type === "webauthn-sign"
      ? {
          credentialId: action.credentialId,
          passkeyLabel: action.passkeyLabel,
          userVerification: action.userVerification,
        }
      : {
          keyLabel: action.keyLabel,
          keyFingerprint: action.keyFingerprint,
        };

  return {
    id: action.id,
    accountId: action.accountId,
    type: action.type,
    source: action.context.source,
    createdAt: new Date(action.createdAt).toISOString(),
    ...ctxFields,
    ...typeFields,
  };
}

function mapContext(context: SignRequestContext): Partial<SigningRequestInsert> {
  switch (context.source) {
    case "agent-proxy":
      return {
        sourceIp: context.sourceIp,
        apiKeyLabel: context.apiKeyLabel,
        apiKeyPrefix: context.apiKeyPrefix,
        clientHostname: context.clientHostname,
        clientOs: context.clientOs,
        clientVersion: context.clientVersion,
      };
    case "endpoint-auth": {
      const base = {
        endpointLabel: context.endpointLabel,
        endpointAddress: context.endpointAddress,
        sourceIp: context.trigger.sourceIp,
      };
      if (context.trigger.kind === "mcp") {
        return {
          ...base,
          mcpReason: context.trigger.reason,
          mcpClientName: context.trigger.mcpClientName,
          mcpClientVersion: context.trigger.mcpClientVersion,
          apiKeyLabel: context.trigger.apiKeyLabel,
          apiKeyPrefix: context.trigger.apiKeyPrefix,
        };
      }
      return base;
    }
    case "agent-forwarding":
      return {
        endpointLabel: context.endpointLabel,
        endpointAddress: context.endpointAddress,
        sessionId: context.sessionId,
      };
  }
}
