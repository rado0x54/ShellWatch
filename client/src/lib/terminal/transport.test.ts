// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it, vi } from "vitest";
import {
  bindTerminal,
  SESSION_CLOSED_BANNER,
  type TerminalSink,
  type TerminalTransport,
  type TerminalView,
} from "./transport.js";

/** A transport the test drives by hand. */
function fakeTransport() {
  let sink: TerminalSink | null = null;
  const stop = vi.fn(() => (sink = null));
  const transport: TerminalTransport = {
    subscribe: (s) => {
      sink = s;
      return stop;
    },
    sendInput: vi.fn(),
    sendResize: vi.fn(),
  };
  return { transport, stop, sink: () => sink };
}

function fakeView() {
  const log: string[] = [];
  const view: TerminalView = {
    reset: () => log.push("reset"),
    write: (d) => log.push(`write:${d}`),
    setInputEnabled: (on) => log.push(`input:${on}`),
  };
  return { view, log };
}

describe("bindTerminal", () => {
  it("writes output, clears on reset, and prints the closed banner", () => {
    const t = fakeTransport();
    const { view, log } = fakeView();
    bindTerminal(view, t.transport);
    t.sink()!.output("a", false);
    t.sink()!.output("b", true);
    t.sink()!.closed();
    expect(log).toEqual(["write:a", "reset", "write:b", `write:${SESSION_CLOSED_BANNER}`]);
  });

  it("follows the mode: observer disables input, control enables it", () => {
    const t = fakeTransport();
    const { view, log } = fakeView();
    const onMode = vi.fn();
    bindTerminal(view, t.transport, onMode);
    t.sink()!.mode?.("observer");
    t.sink()!.mode?.("control");
    expect(log).toEqual(["input:false", "input:true"]);
    expect(onMode.mock.calls).toEqual([["observer"], ["control"]]);
  });

  it("returns the transport's unsubscribe", () => {
    const t = fakeTransport();
    const unbind = bindTerminal(fakeView().view, t.transport);
    unbind();
    expect(t.stop).toHaveBeenCalledOnce();
    expect(t.sink()).toBeNull();
  });
});
