import type { KeyBinding as TextareaKeyBinding } from "@opentui/core";

const ENTER_KEY_NAMES = new Set(["return", "enter", "kpenter", "linefeed"]);
const SHIFT_ENTER_SEQUENCES = new Set(["\u001b[13;2u", "\u001b[27;2;13~"]);

export function isChatNewlineKey(key: {
  name: string;
  shift?: boolean;
  ctrl?: boolean;
  meta?: boolean;
  raw?: string;
}): boolean {
  if (key.raw && SHIFT_ENTER_SEQUENCES.has(key.raw)) return true;
  return (
    ENTER_KEY_NAMES.has(key.name) && Boolean(key.shift || key.ctrl || key.meta)
  );
}

/** Enter submits; modified Enter and Ctrl+J insert newlines. */
export const CHAT_KEY_BINDINGS: TextareaKeyBinding[] = [
  { name: "return", action: "submit" },
  { name: "kpenter", action: "submit" },
  { name: "linefeed", action: "newline" },
  { name: "return", shift: true, action: "newline" },
  { name: "kpenter", shift: true, action: "newline" },
  { name: "linefeed", shift: true, action: "newline" },
  { name: "return", ctrl: true, action: "newline" },
  { name: "kpenter", ctrl: true, action: "newline" },
  { name: "return", meta: true, action: "newline" },
  { name: "kpenter", meta: true, action: "newline" },
];
