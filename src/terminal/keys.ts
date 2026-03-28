const KEY_MAP: Record<string, string> = {
  "ctrl+c": "\x03",
  "ctrl+d": "\x04",
  "ctrl+z": "\x1a",
  "ctrl+l": "\x0c",
  "ctrl+a": "\x01",
  "ctrl+e": "\x05",
  "ctrl+u": "\x15",
  "ctrl+k": "\x0b",
  "ctrl+w": "\x17",
  tab: "\t",
  enter: "\r",
  escape: "\x1b",
  up: "\x1b[A",
  down: "\x1b[B",
  right: "\x1b[C",
  left: "\x1b[D",
  home: "\x1b[H",
  end: "\x1b[F",
  backspace: "\x7f",
  delete: "\x1b[3~",
};

export function resolveKey(key: string): string {
  // Named key
  const mapped = KEY_MAP[key.toLowerCase()];
  if (mapped) return mapped;

  // Raw text escape: "text:hello\n"
  if (key.startsWith("text:")) {
    return key.slice(5).replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t");
  }

  throw new Error(
    `Unknown key: ${key}. Use one of: ${Object.keys(KEY_MAP).join(", ")}, or text:<raw>`,
  );
}

export function resolveKeys(keys: string[]): string {
  return keys.map(resolveKey).join("");
}

export const SUPPORTED_KEYS = Object.keys(KEY_MAP);
