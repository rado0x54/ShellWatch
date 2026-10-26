// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Long-error toast presentation (#252): toasts hold a short headline; the
// full text moves behind a "Details" affordance.
import { describe, expect, it } from "vitest";
import { get } from "svelte/store";
import type { AppNotification } from "./notifications.js";
import {
  splitLongMessage,
  toastError,
  toastNotification,
  toastRequestError,
  toasts,
  TOAST_SUMMARY_MAX,
} from "./toasts.js";

describe("splitLongMessage", () => {
  it("passes short messages through unchanged", () => {
    const { message, detail } = splitLongMessage("Failed to deny action");
    expect(message).toBe("Failed to deny action");
    expect(detail).toBeUndefined();
  });

  it("summarizes a long message at a clause boundary and keeps the full text", () => {
    const long =
      "Failed to create session: Failed to connect to 1e08ce0d-2cb7-41e1-826c-24b40808428d: " +
      "SSH connection to de.v.riedel.nyc:22 refused: host key mismatch: the server presented " +
      "SHA256:zVoS+R4wxwH6Pxwh5dkP/JTQ8LfGcTZ03TFXBsxgmY4 (ssh-ed25519) but " +
      "SHA256:qOLXtBnKByIs58QnXYEDxDQusJSVATH2dz5mXmomRRg is pinned for this endpoint; " +
      "connection refused before authentication.";
    const { message, detail } = splitLongMessage(long);
    expect(message.length).toBeLessThanOrEqual(TOAST_SUMMARY_MAX + 1);
    expect(message.endsWith("…")).toBe(true);
    // The cut lands on a clause boundary, not mid-fingerprint.
    expect(message).toBe(
      "Failed to create session: Failed to connect to 1e08ce0d-2cb7-41e1-826c-24b40808428d: " +
        "SSH connection to de.v.riedel.nyc:22 refused: host key mismatch…",
    );
    expect(detail).toBe(long);
  });

  it("falls back to a word boundary, then a hard cut", () => {
    const words = `${"word ".repeat(60)}end`;
    const atWord = splitLongMessage(words);
    expect(atWord.message.endsWith("word…")).toBe(true);
    expect(atWord.detail).toBe(words);

    const blob = "x".repeat(400);
    const hard = splitLongMessage(blob);
    expect(hard.message).toBe(`${"x".repeat(TOAST_SUMMARY_MAX)}…`);
    expect(hard.detail).toBe(blob);
  });
});

describe("toastError", () => {
  it("auto-splits long messages and keeps explicit details as-is", () => {
    toasts.set([]);
    const long = `Something broke: ${"y".repeat(300)}`;
    toastError(long);
    toastError("Headline only", "full explicit detail");
    const [auto, explicit] = get(toasts);
    expect(auto.message.length).toBeLessThanOrEqual(TOAST_SUMMARY_MAX + 1);
    expect(auto.detail).toBe(long);
    expect(explicit.message).toBe("Headline only");
    expect(explicit.detail).toBe("full explicit detail");
    toasts.set([]);
  });
});

function mismatchNotification(): AppNotification {
  return {
    id: "ntf-1",
    accountId: "acc",
    type: "host-key-mismatch",
    severity: "error",
    title: 'Host key MISMATCH — connection to "VPS (DE)" blocked',
    detail: "Presented: SHA256:x\nPinned: SHA256:y",
    payload: { endpointId: "e1" },
    createdAt: "2026-01-01T00:00:00.000Z",
  };
}

describe("notification toast dedupe (#252)", () => {
  it("WS first: the HTTP error referencing the same notification is suppressed", () => {
    toasts.set([]);
    toastNotification(mismatchNotification());
    toastRequestError("Failed to create session: host key mismatch: ...", "ntf-1");
    const all = get(toasts);
    expect(all).toHaveLength(1);
    expect(all[0].notificationId).toBe("ntf-1");
    // Error severity stays until dismissed and carries the typed action link.
    expect(all[0].dismissAfterMs).toBeUndefined();
    expect(all[0].link).toEqual({ href: "/settings/endpoints", label: "Review endpoint" });
    toasts.set([]);
  });

  it("HTTP first (WS alert lost): the error still surfaces, and a late push replaces it", () => {
    toasts.set([]);
    toastRequestError("Failed to create session: host key mismatch: ...", "ntf-1");
    expect(get(toasts)).toHaveLength(1);
    toastNotification(mismatchNotification());
    const all = get(toasts);
    expect(all).toHaveLength(1);
    expect(all[0].message).toContain("Host key MISMATCH");
    toasts.set([]);
  });

  it("an error without a notification id always surfaces", () => {
    toasts.set([]);
    toastRequestError("Failed to create session: connection refused");
    expect(get(toasts)).toHaveLength(1);
    toasts.set([]);
  });

  it("unknown notification kinds render without a typed action", () => {
    toasts.set([]);
    toastNotification({
      ...mismatchNotification(),
      id: "ntf-2",
      type: "future-kind",
      severity: "info",
    });
    const [t] = get(toasts);
    expect(t.link).toBeUndefined();
    expect(t.dismissAfterMs).toBe(10_000);
    toasts.set([]);
  });
});
