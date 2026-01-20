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

export namespace Keybind {

  export type Info = Pick<ParsedKey, "name" | "ctrl" | "meta" | "shift" | "super"> & {
    sequence?: string;
  };

  export function fromParsedKey(key: ParsedKey, leader = false): Info {
    return {
      name: key.name,
      ctrl: key.ctrl,
      meta: key.meta,
      shift: key.shift,
      super: key.super ?? false,
      sequence: key.sequence,
    }
  }

  export function toString(info: Info | undefined): string {
    if (!info) return "";
    const parts: string[] = [];

    if (info.ctrl) parts.push("ctrl");
    if (info.meta) parts.push("alt");
    if (info.super) parts.push("super");
    if (info.shift) parts.push("shift");
    if (info.name) {
      if (info.name === "delete") parts.push("del")
      else parts.push(info.name);
    }

    let result = parts.join("+");

    return result
  }

  export function parse(key: string): Info[] {
    if(key === "none") return [];


    return key.split(",").map((c) => {
      const parts = c.split("+");

      const info: Info = {
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
              // If it's a single character that differs from lowercase, treat as sequence
              // e.g., "?" or "!" - these are produced by shift+key combos
              if (part.length === 1 && part !== lowerPart) {
                info.sequence = part;
              } else {
                info.name = lowerPart;
              }
              break;
          }
      }

      return info;
    })
  }

  export function matches(pressed: Info, combo: Info): boolean {
    // If combo has a sequence defined, match by sequence
    if (combo.sequence) {
      return pressed.sequence === combo.sequence &&
        pressed.ctrl === combo.ctrl &&
        pressed.meta === combo.meta &&
        (pressed.super ?? false) === (combo.super ?? false);
    }

    // Handle control character sequences (e.g., "\x03" for Ctrl+C)
    if (combo.ctrl && combo.name && pressed.sequence) {
      const charCode = pressed.sequence.charCodeAt(0);
      // Control characters are ASCII 1-26, corresponding to Ctrl+A through Ctrl+Z
      if (charCode >= 1 && charCode <= 26) {
        const expectedChar = String.fromCharCode(charCode + 96); // 1 -> 'a', 2 -> 'b', etc.
        if (combo.name === expectedChar) {
          return pressed.meta === combo.meta &&
            (pressed.super ?? false) === (combo.super ?? false);
        }
      }
    }

    // Otherwise match by name and modifiers
    return pressed.name === combo.name &&
      pressed.ctrl === combo.ctrl &&
      pressed.meta === combo.meta &&
      pressed.shift === combo.shift &&
      (pressed.super ?? false) === (combo.super ?? false);
  }
}

