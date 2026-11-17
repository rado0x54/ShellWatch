// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * The one xterm look (#328): the session terminal, the guest page, the
 * observer grid and the sign-page snapshot all build on these.
 */
import type { ITheme } from "@xterm/xterm";

export const TERMINAL_FONT_FAMILY =
  "'Geist Mono', 'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace";

export const TERMINAL_THEME: ITheme = {
  background: "#0e0e0e",
  foreground: "#f2f2f2",
  cursor: "#69f6b8",
  cursorAccent: "#002919",
  selectionBackground: "rgba(105, 246, 184, 0.25)",
  black: "#0e0e0e",
  red: "#ff5a5a",
  green: "#69f6b8",
  yellow: "#f8a010",
  blue: "#3fbe8a",
  magenta: "#b07a1a",
  cyan: "#69f6b8",
  white: "#adaaaa",
  brightBlack: "#494847",
  brightRed: "#ff5a5a",
  brightGreen: "#69f6b8",
  brightYellow: "#f8a010",
  brightBlue: "#3fbe8a",
  brightMagenta: "#b07a1a",
  brightCyan: "#69f6b8",
  brightWhite: "#f2f2f2",
};

/** A read-only view: the theme with a fully transparent cursor. */
export const READONLY_TERMINAL_THEME: ITheme = { ...TERMINAL_THEME, cursor: "#00000000" };
