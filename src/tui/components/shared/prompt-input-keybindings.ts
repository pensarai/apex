import type { KeyBinding as TextareaKeyBinding } from "@opentui/core";

const ENTER_KEY_NAMES = new Set(["return", "enter", "kpenter", "linefeed"]);
// Raw escape sequences for modified Enter under Kitty (`allKeysAsEscapes`) and
// legacy modifyOtherKeys. Terminals that deliver these without parsed modifier
// flags would otherwise submit instead of inserting a newline. Modifier codes:
// 2=Shift, 3=Alt/Option, 5=Ctrl (Kitty CSI-u `13;<mod>u`; legacy `27;<mod>;13~`).
const MODIFIED_ENTER_SEQUENCES = new Set([
  "\u001b[13;2u",
  "\u001b[13;3u",
  "\u001b[13;5u",
  "\u001b[27;2;13~",
  "\u001b[27;3;13~",
  "\u001b[27;5;13~",
]);

export function isChatNewlineKey(key: {
  name: string;
  shift?: boolean;
  ctrl?: boolean;
  meta?: boolean;
  raw?: string;
}): boolean {
  if (key.raw && MODIFIED_ENTER_SEQUENCES.has(key.raw)) return true;
  return (
    ENTER_KEY_NAMES.has(key.name) && Boolean(key.shift || key.ctrl || key.meta)
  );
}

/** Enter submits; modified Enter and Ctrl+J insert newlines. */
export const CHAT_KEY_BINDINGS: TextareaKeyBinding[] = [
  { name: "return", action: "submit" },
  { name: "enter", action: "submit" },
  { name: "kpenter", action: "submit" },
  { name: "linefeed", action: "newline" },
  { name: "j", ctrl: true, action: "newline" },
  { name: "return", shift: true, action: "newline" },
  { name: "enter", shift: true, action: "newline" },
  { name: "kpenter", shift: true, action: "newline" },
  { name: "linefeed", shift: true, action: "newline" },
  { name: "return", ctrl: true, action: "newline" },
  { name: "enter", ctrl: true, action: "newline" },
  { name: "kpenter", ctrl: true, action: "newline" },
  { name: "return", meta: true, action: "newline" },
  { name: "enter", meta: true, action: "newline" },
  { name: "kpenter", meta: true, action: "newline" },
];
