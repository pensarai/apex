/**
 * Editing Actions
 *
 * Defines vim-like editing actions for the leader key system.
 * Each action operates on an InputBuffer instance.
 */

import type { InputBuffer } from "./input-buffer";

// ============================================
// Action Types
// ============================================

export type ActionCategory = "movement" | "selection" | "editing" | "clipboard" | "history" | "misc";

export interface Action {
  id: string;
  key: string;
  description: string;
  category: ActionCategory;
  execute: (buffer: InputBuffer) => void;
}

// ============================================
// Movement Actions
// ============================================

export const movementActions: Action[] = [
  {
    id: "move-left",
    key: "h",
    description: "Move cursor left",
    category: "movement",
    execute: (buffer) => buffer.moveLeft(),
  },
  {
    id: "move-right",
    key: "l",
    description: "Move cursor right",
    category: "movement",
    execute: (buffer) => buffer.moveRight(),
  },
  {
    id: "move-word-left",
    key: "b",
    description: "Move cursor to previous word",
    category: "movement",
    execute: (buffer) => buffer.moveWordLeft(),
  },
  {
    id: "move-word-right",
    key: "w",
    description: "Move cursor to next word",
    category: "movement",
    execute: (buffer) => buffer.moveWordRight(),
  },
  {
    id: "move-to-start",
    key: "0",
    description: "Move cursor to start of line",
    category: "movement",
    execute: (buffer) => buffer.moveToStart(),
  },
  {
    id: "move-to-end",
    key: "$",
    description: "Move cursor to end of line",
    category: "movement",
    execute: (buffer) => buffer.moveToEnd(),
  },
  {
    id: "move-to-first-char",
    key: "^",
    description: "Move to first non-whitespace character",
    category: "movement",
    execute: (buffer) => {
      buffer.moveToStart();
      const text = buffer.getText();
      let pos = 0;
      while (pos < text.length && /\s/.test(text[pos])) {
        pos++;
      }
      buffer.moveCursor(pos);
    },
  },
];

// ============================================
// Selection Actions
// ============================================

export const selectionActions: Action[] = [
  {
    id: "select-char-left",
    key: "H",
    description: "Select character left",
    category: "selection",
    execute: (buffer) => buffer.moveLeft(true),
  },
  {
    id: "select-char-right",
    key: "L",
    description: "Select character right",
    category: "selection",
    execute: (buffer) => buffer.moveRight(true),
  },
  {
    id: "select-word-left",
    key: "B",
    description: "Select to previous word",
    category: "selection",
    execute: (buffer) => buffer.moveWordLeft(true),
  },
  {
    id: "select-word-right",
    key: "W",
    description: "Select to next word",
    category: "selection",
    execute: (buffer) => buffer.moveWordRight(true),
  },
  {
    id: "select-to-start",
    key: "g0",
    description: "Select to start of line",
    category: "selection",
    execute: (buffer) => buffer.moveToStart(true),
  },
  {
    id: "select-to-end",
    key: "g$",
    description: "Select to end of line",
    category: "selection",
    execute: (buffer) => buffer.moveToEnd(true),
  },
  {
    id: "select-all",
    key: "V",
    description: "Select all",
    category: "selection",
    execute: (buffer) => buffer.selectAll(),
  },
  {
    id: "select-word",
    key: "v",
    description: "Select current word",
    category: "selection",
    execute: (buffer) => buffer.selectWord(),
  },
  {
    id: "clear-selection",
    key: "Escape",
    description: "Clear selection",
    category: "selection",
    execute: (buffer) => buffer.clearSelection(),
  },
];

// ============================================
// Editing Actions
// ============================================

export const editingActions: Action[] = [
  {
    id: "delete-char",
    key: "x",
    description: "Delete character under cursor",
    category: "editing",
    execute: (buffer) => buffer.delete(),
  },
  {
    id: "delete-char-before",
    key: "X",
    description: "Delete character before cursor",
    category: "editing",
    execute: (buffer) => buffer.backspace(),
  },
  {
    id: "delete-word",
    key: "dw",
    description: "Delete word forward",
    category: "editing",
    execute: (buffer) => buffer.deleteWord(),
  },
  {
    id: "delete-word-backward",
    key: "db",
    description: "Delete word backward",
    category: "editing",
    execute: (buffer) => buffer.deleteWordBackward(),
  },
  {
    id: "delete-to-end",
    key: "D",
    description: "Delete to end of line",
    category: "editing",
    execute: (buffer) => buffer.deleteToEnd(),
  },
  {
    id: "delete-to-start",
    key: "d0",
    description: "Delete to start of line",
    category: "editing",
    execute: (buffer) => buffer.deleteToStart(),
  },
  {
    id: "delete-line",
    key: "dd",
    description: "Delete entire line",
    category: "editing",
    execute: (buffer) => buffer.clear(),
  },
  {
    id: "change-word",
    key: "cw",
    description: "Change word (delete and enter insert mode)",
    category: "editing",
    execute: (buffer) => buffer.deleteWord(),
  },
  {
    id: "change-to-end",
    key: "C",
    description: "Change to end of line",
    category: "editing",
    execute: (buffer) => buffer.deleteToEnd(),
  },
];

// ============================================
// Clipboard Actions
// ============================================

export const clipboardActions: Action[] = [
  {
    id: "yank",
    key: "y",
    description: "Yank (copy) selection",
    category: "clipboard",
    execute: (buffer) => buffer.yank(),
  },
  {
    id: "yank-line",
    key: "yy",
    description: "Yank entire line",
    category: "clipboard",
    execute: (buffer) => {
      buffer.selectAll();
      buffer.yank();
      buffer.clearSelection();
    },
  },
  {
    id: "paste",
    key: "p",
    description: "Paste after cursor",
    category: "clipboard",
    execute: (buffer) => buffer.paste(),
  },
  {
    id: "paste-before",
    key: "P",
    description: "Paste before cursor",
    category: "clipboard",
    execute: (buffer) => buffer.paste(),
  },
];

// ============================================
// History Actions
// ============================================

export const historyActions: Action[] = [
  {
    id: "undo",
    key: "u",
    description: "Undo last change",
    category: "history",
    execute: (buffer) => buffer.undo(),
  },
  {
    id: "redo",
    key: "ctrl+r",
    description: "Redo last undone change",
    category: "history",
    execute: (buffer) => buffer.redo(),
  },
];

// ============================================
// All Actions
// ============================================

export const allActions: Action[] = [
  ...movementActions,
  ...selectionActions,
  ...editingActions,
  ...clipboardActions,
  ...historyActions,
];

// ============================================
// Action Lookup
// ============================================

export const actionsByKey = new Map<string, Action>(
  allActions.map((action) => [action.key, action])
);

export const actionsById = new Map<string, Action>(
  allActions.map((action) => [action.id, action])
);

export function getAction(keyOrId: string): Action | undefined {
  return actionsByKey.get(keyOrId) || actionsById.get(keyOrId);
}

export function getActionsByCategory(category: ActionCategory): Action[] {
  return allActions.filter((action) => action.category === category);
}
