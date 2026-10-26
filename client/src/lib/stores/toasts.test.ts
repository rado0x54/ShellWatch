// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Long-error toast presentation (#252): toasts hold a short headline; the
// full text moves behind a "Details" affordance.
import { describe, expect, it } from "vitest";
import { get } from "svelte/store";
import { splitLongMessage, toastError, toasts, TOAST_SUMMARY_MAX } from "./toasts.js";

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
