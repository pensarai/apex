import type { KeyBinding as TextareaKeyBinding } from "@opentui/core";

/**
 * Chat-style keybindings: Enter submits, Shift+Enter / Ctrl+J inserts newline.
 * Overrides @opentui defaults (return=newline, Cmd+return=submit).
 *
 * Both "return" (\r) and "linefeed" (\n) need shift variants because
 * @opentui matches modifiers exactly (Kitty protocol reports shift explicitly).
 */
export const chatKeyBindings: TextareaKeyBinding[] = [
  { name: "return", action: "submit" },
  { name: "enter", action: "submit" },
  { name: "linefeed", action: "newline" },
  { name: "return", shift: true, action: "newline" },
  { name: "enter", shift: true, action: "newline" },
  { name: "linefeed", shift: true, action: "newline" },
];

export const redirectKeyBindings: TextareaKeyBinding[] = [...chatKeyBindings];
