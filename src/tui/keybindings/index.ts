/**
 * Keybindings Module
 *
 * Exports all keybinding-related functionality including:
 * - Leader key system
 * - Input buffer for text operations
 * - Editing actions
 */

import type { ParsedKey } from "@opentui/core";

export {
  LeaderKeyProvider,
  useLeaderKey,
  type LeaderKeyState,
  type LeaderKeyContextValue,
} from "./keybind";

export {
  InputBuffer,
  type InputState,
  type Selection,
  type UndoEntry,
} from "./input-buffer";

export {
  allActions,
  getAction,
  getActionsByCategory,
  actionsByKey,
  actionsById,
  movementActions,
  selectionActions,
  editingActions,
  clipboardActions,
  historyActions,
  type Action,
  type ActionCategory,
} from "./actions";

export {
  createKeybindings,
  type KeybindingEntry,
  type KeybindingDependencies,
} from "./registry";

export {
  shouldHandlePromptSensitiveShortcut,
  type PromptSensitiveShortcutContext,
} from "./guards";

export type KeybindInfo = Pick<
  ParsedKey,
  "name" | "ctrl" | "meta" | "shift" | "super"
> & {
  sequence?: string;
};

export function fromParsedKey(key: ParsedKey, _leader = false): KeybindInfo {
  return {
    name: key.name,
    ctrl: key.ctrl,
    meta: key.meta,
    shift: key.shift,
    super: key.super ?? false,
    sequence: key.sequence,
  };
}

export function keybindToString(info: KeybindInfo | undefined): string {
  if (!info) return "";
  const parts: string[] = [];

  if (info.ctrl) parts.push("ctrl");
  if (info.meta) parts.push("alt");
  if (info.super) parts.push("super");
  if (info.shift) parts.push("shift");
  if (info.name) {
    if (info.name === "delete") parts.push("del");
    else parts.push(info.name);
  }

  const result = parts.join("+");

  return result;
}

export function parseKeybind(key: string): KeybindInfo[] {
  if (key === "none") return [];

  return key.split(",").map((c) => {
    const parts = c.split("+");

    const info: KeybindInfo = {
      ctrl: false,
      meta: false,
      shift: false,
      name: "",
      sequence: undefined,
    };

    for (const part of parts) {
      const lowerPart = part.toLowerCase();
      switch (lowerPart) {
        case "ctrl":
          info.ctrl = true;
          break;
        case "alt":
        case "meta":
        case "option":
          info.meta = true;
          break;
        case "super":
          info.super = true;
          break;
        case "shift":
          info.shift = true;
          break;
        case "esc":
          info.name = "escape";
          break;
        default:
          if (part.length === 1 && part !== lowerPart) {
            info.sequence = part;
          } else {
            info.name = lowerPart;
          }
          break;
      }
    }

    return info;
  });
}

export function matchesKeybind(
  pressed: KeybindInfo,
  combo: KeybindInfo,
): boolean {
  if (combo.sequence) {
    return (
      pressed.sequence === combo.sequence &&
      pressed.ctrl === combo.ctrl &&
      pressed.meta === combo.meta &&
      (pressed.super ?? false) === (combo.super ?? false)
    );
  }

  if (combo.ctrl && combo.name && pressed.sequence) {
    const charCode = pressed.sequence.charCodeAt(0);
    if (charCode >= 1 && charCode <= 26) {
      const expectedChar = String.fromCharCode(charCode + 96);
      if (combo.name === expectedChar) {
        return (
          pressed.meta === combo.meta &&
          (pressed.super ?? false) === (combo.super ?? false)
        );
      }
    }
  }

  return (
    pressed.name === combo.name &&
    pressed.ctrl === combo.ctrl &&
    pressed.meta === combo.meta &&
    pressed.shift === combo.shift &&
    (pressed.super ?? false) === (combo.super ?? false)
  );
}
