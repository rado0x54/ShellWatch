// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { FastifyRequest, preHandlerHookHandler } from "fastify";
import {
  consumeStepUpToken,
  type ConsumeFailureReason,
  type StepUpAction,
} from "./stepup-store.js";

const STEPUP_HEADER = "x-shellwatch-stepup-token";

/** Pull the step-up token off the request header. */
function extractStepUpToken(request: FastifyRequest): string | null {
  const header = request.headers[STEPUP_HEADER];
  if (typeof header === "string" && header.length > 0) return header;
  if (Array.isArray(header) && header.length > 0 && typeof header[0] === "string") {
    return header[0];
  }
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

/**
 * Build a Fastify `preHandler` hook that consumes a step-up token bound to
 * the given action. Wire it into a route's options:
 *
 *     app.post("/api/webauthn/credentials/:id/revoke", {
 *       preHandler: requireStepUp(STEPUP_ACTION.revokePasskey),
 *     }, handler);
 *
 * On success the hook logs `passkey_stepup.consumed` and returns; the route
 * handler runs as normal. On failure it logs `passkey_stepup.rejected` (warn
 * level — the most useful signal for incident detection on a sensitive
 * endpoint) and sends a 401 with a machine-readable code, which short-
 * circuits the request before the handler runs.
 *
 * Tokens are single-use and burn on first read regardless of match outcome,
 * so an attacker can't probe one token across actions.
 */
export function requireStepUp(action: StepUpAction): preHandlerHookHandler {
  return async (request, reply) => {
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
      return;
    }

    request.log.warn(
      {
        event: "passkey_stepup.rejected",
        accountId: request.accountId,
        action,
        reason: result.reason,
      },
      "step-up token rejected",
    );
    await reply.status(401).send({
      error: ERROR_MESSAGE[result.reason],
      code: ERROR_CODE[result.reason],
    });
  };
}
