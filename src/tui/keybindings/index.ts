/**
 * Keybindings Module
 *
 * Exports all keybinding-related functionality including:
 * - Leader key system
 * - Input buffer for text operations
 * - Editing actions
 */

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
  type KeybindingActionContext,
  type KeybindingDependencies,
} from "./registry";

export {
  createKeybindingRegistry,
  registerKeybinding,
  resolveKeybinding,
  formatKeybindingCombo,
  type KeybindingScope,
  type KeybindingDefinition,
  type KeybindingRegistry,
  type RegisteredKeybinding,
  type KeybindingRuntimeContext,
} from "./system";

export {
  shouldHandlePromptSensitiveShortcut,
  type PromptSensitiveShortcutContext,
} from "./guards";

export {
  fromParsedKey,
  keybindToString,
  parseKeybind,
  matchesKeybind,
  type KeybindInfo,
} from "./parser";
