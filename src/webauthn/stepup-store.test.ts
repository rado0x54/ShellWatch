import { afterEach, describe, expect, it } from "vitest";
import {
  _resetStepUpStore,
  consumeStepUpToken,
  mintStepUpToken,
  STEPUP_ACTION,
} from "./stepup-store.js";

const ACCOUNT_A = "00000000-0000-0000-0000-0000000000aa";
const ACCOUNT_B = "00000000-0000-0000-0000-0000000000bb";

describe("step-up token store", () => {
  afterEach(() => {
    _resetStepUpStore();
  });

  it("mint then consume returns ok exactly once", () => {
    const minted = mintStepUpToken({
      accountId: ACCOUNT_A,
      action: STEPUP_ACTION.registerPasskey,
    });

    const first = consumeStepUpToken({
      token: minted.token,
      accountId: ACCOUNT_A,
      action: STEPUP_ACTION.registerPasskey,
    });
    expect(first.ok).toBe(true);

    const second = consumeStepUpToken({
      token: minted.token,
      accountId: ACCOUNT_A,
      action: STEPUP_ACTION.registerPasskey,
    });
    expect(second.ok).toBe(false);
    expect((second as { ok: false; reason: string }).reason).toBe("missing");
  });

  it("rejects token presented for the wrong action", () => {
    const minted = mintStepUpToken({
      accountId: ACCOUNT_A,
      action: STEPUP_ACTION.registerPasskey,
    });
    const result = consumeStepUpToken({
      token: minted.token,
      accountId: ACCOUNT_A,
      action: STEPUP_ACTION.revokePasskey,
    });
    expect(result.ok).toBe(false);
    expect((result as { ok: false; reason: string }).reason).toBe("wrong_action");
    // And the token is burnt either way (single-use, even on failure).
    const retry = consumeStepUpToken({
      token: minted.token,
      accountId: ACCOUNT_A,
      action: STEPUP_ACTION.registerPasskey,
    });
    expect(retry.ok).toBe(false);
  });

  it("rejects token presented by the wrong account", () => {
    const minted = mintStepUpToken({
      accountId: ACCOUNT_A,
      action: STEPUP_ACTION.revokePasskey,
    });
    const result = consumeStepUpToken({
      token: minted.token,
      accountId: ACCOUNT_B,
      action: STEPUP_ACTION.revokePasskey,
    });
    expect(result.ok).toBe(false);
    expect((result as { ok: false; reason: string }).reason).toBe("wrong_account");
  });

  it("rejects an expired token", () => {
    const minted = mintStepUpToken({
      accountId: ACCOUNT_A,
      action: STEPUP_ACTION.registerPasskey,
      ttlMs: 1,
    });
    // Wait past the TTL by busy-spinning briefly. setTimeout would also work,
    // but a synchronous loop keeps the test deterministic.
    const deadline = Date.now() + 5;
    while (Date.now() < deadline) {
      /* spin */
    }
    const result = consumeStepUpToken({
      token: minted.token,
      accountId: ACCOUNT_A,
      action: STEPUP_ACTION.registerPasskey,
    });
    expect(result.ok).toBe(false);
    expect((result as { ok: false; reason: string }).reason).toBe("expired");
  });

  it("rejects a missing/empty token", () => {
    expect(
      consumeStepUpToken({
        token: undefined,
        accountId: ACCOUNT_A,
        action: STEPUP_ACTION.registerPasskey,
      }).ok,
    ).toBe(false);
    expect(
      consumeStepUpToken({
        token: "",
        accountId: ACCOUNT_A,
        action: STEPUP_ACTION.registerPasskey,
      }).ok,
    ).toBe(false);
    expect(
      consumeStepUpToken({
        token: "not-a-real-token",
        accountId: ACCOUNT_A,
        action: STEPUP_ACTION.registerPasskey,
      }).ok,
    ).toBe(false);
  });
});
