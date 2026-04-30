import type { FastifyReply, FastifyRequest } from "fastify";
import {
  consumeStepUpToken,
  type ConsumeFailureReason,
  type StepUpAction,
} from "./stepup-store.js";

const STEPUP_HEADER = "x-shellwatch-stepup-token";

/**
 * Pull the step-up token off the request. Header takes precedence so the
 * client doesn't have to splice it into a body that may already have a
 * narrow schema (e.g. the registration verify body). Body is the fallback
 * for callers that find headers awkward (and for parity with how the issue
 * spec was written).
 */
function extractStepUpToken(request: FastifyRequest): string | null {
  const header = request.headers[STEPUP_HEADER];
  if (typeof header === "string" && header.length > 0) return header;
  if (Array.isArray(header) && header.length > 0 && typeof header[0] === "string") {
    return header[0];
  }
  const body = request.body as { stepUpToken?: unknown } | undefined;
  if (body && typeof body.stepUpToken === "string") return body.stepUpToken;
  return null;
}

const ERROR_CODE: Record<ConsumeFailureReason, string> = {
  missing: "stepup_required",
  expired: "stepup_expired",
  wrong_action: "stepup_wrong_action",
  wrong_account: "stepup_wrong_account",
};

const ERROR_MESSAGE: Record<ConsumeFailureReason, string> = {
  missing: "Step-up authentication required",
  expired: "Step-up token expired",
  wrong_action: "Step-up token not valid for this action",
  wrong_account: "Step-up token not valid for this account",
};

export interface RequireStepUpParams {
  request: FastifyRequest;
  reply: FastifyReply;
  action: StepUpAction;
}

/**
 * Consume a step-up token off the request. Single-use: the token is removed
 * on first read regardless of whether the action / account match. On
 * failure, sets the response to 401 with a machine-readable error code so
 * the client can prompt the user to re-authenticate, and returns false.
 */
export function requireStepUp(params: RequireStepUpParams): boolean {
  const { request, reply, action } = params;
  const token = extractStepUpToken(request);
  const result = consumeStepUpToken({
    token,
    accountId: request.accountId,
    action,
  });
  if (result.ok) {
    request.log.info(
      { event: "passkey_stepup.consumed", accountId: request.accountId, action },
      "step-up token consumed",
    );
    return true;
  }

  // Rejections are the most interesting line for incident detection — a
  // wrong-account or wrong-action rejection on an authenticated session is
  // either a buggy client or an attacker probing.
  request.log.warn(
    {
      event: "passkey_stepup.rejected",
      accountId: request.accountId,
      action,
      reason: result.reason,
    },
    "step-up token rejected",
  );
  reply.status(401);
  reply.send({
    error: ERROR_MESSAGE[result.reason],
    code: ERROR_CODE[result.reason],
  });
  return false;
}
