/**
 * Leader Key Manager
 *
 * Implements a vim-like leader key system for advanced keyboard shortcuts.
 * Leader key (Ctrl+Space) activates a mode where subsequent keys trigger actions.
 *
 * Example usage:
 *   Ctrl+Space, w  -> Move word right
 *   Ctrl+Space, dd -> Delete line
 *   Ctrl+Space, ?  -> Show help overlay
 */

import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useMemo,
  type ReactNode,
} from "react";
import { useKeyboard } from "@opentui/react";
import { InputBuffer } from "./input-buffer";
import { allActions, getAction, type Action, type ActionCategory } from "./actions";
import { colors } from "../theme";

// ============================================
// Context Types
// ============================================

export interface LeaderKeyState {
  /** Whether leader mode is active */
  isActive: boolean;
  /** Current key sequence being built */
  keySequence: string;
  /** Last executed action */
  lastAction: Action | null;
  /** Show help overlay */
  showHelp: boolean;
  /** Input buffer for text operations */
  buffer: InputBuffer;
}

export interface LeaderKeyContextValue extends LeaderKeyState {
  /** Activate leader mode */
  activate: () => void;
  /** Deactivate leader mode */
  deactivate: () => void;
  /** Toggle leader mode */
  toggle: () => void;
  /** Toggle help overlay */
  toggleHelp: () => void;
  /** Execute an action by key or id */
  executeAction: (keyOrId: string) => boolean;
  /** Get text from buffer */
  getText: () => string;
  /** Set text in buffer */
  setText: (text: string) => void;
  /** Get cursor position */
  getCursor: () => number;
  /** Check if selection is active */
  hasSelection: () => boolean;
}

// ============================================
// Context
// ============================================

const LeaderKeyContext = createContext<LeaderKeyContextValue | null>(null);

// ============================================
// Hook
// ============================================

export function useLeaderKey(): LeaderKeyContextValue {
  const context = useContext(LeaderKeyContext);
  if (!context) {
    throw new Error("useLeaderKey must be used within a LeaderKeyProvider");
  }
  return context;
}

// ============================================
// Provider
// ============================================

interface LeaderKeyProviderProps {
  children: ReactNode;
  /** Leader key combination (default: Ctrl+Space) */
  leaderKey?: string;
  /** Timeout for key sequence (ms) */
  sequenceTimeout?: number;
  /** Initial text */
  initialText?: string;
  /** Callback when text changes */
  onTextChange?: (text: string) => void;
}

export function LeaderKeyProvider({
  children,
  leaderKey = "ctrl+space",
  sequenceTimeout = 1000,
  initialText = "",
  onTextChange,
}: LeaderKeyProviderProps) {
  const [isActive, setIsActive] = useState(false);
  const [keySequence, setKeySequence] = useState("");
  const [lastAction, setLastAction] = useState<Action | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const [buffer] = useState(() => new InputBuffer(initialText));

  // Sync buffer with external text changes
  useEffect(() => {
    if (initialText !== buffer.getText()) {
      buffer.setText(initialText);
    }
  }, [initialText, buffer]);

  // Notify on text changes
  useEffect(() => {
    if (onTextChange) {
      const text = buffer.getText();
      onTextChange(text);
    }
  }, [buffer, onTextChange]);

  // Clear key sequence after timeout
  useEffect(() => {
    if (keySequence && isActive) {
      const timer = setTimeout(() => {
        setKeySequence("");
        setIsActive(false);
      }, sequenceTimeout);
      return () => clearTimeout(timer);
    }
  }, [keySequence, isActive, sequenceTimeout]);

  // Activate leader mode
  const activate = useCallback(() => {
    setIsActive(true);
    setKeySequence("");
  }, []);

  // Deactivate leader mode
  const deactivate = useCallback(() => {
    setIsActive(false);
    setKeySequence("");
  }, []);

  // Toggle leader mode
  const toggle = useCallback(() => {
    if (isActive) {
      deactivate();
    } else {
      activate();
    }
  }, [isActive, activate, deactivate]);

  // Toggle help overlay
  const toggleHelp = useCallback(() => {
    setShowHelp((prev) => !prev);
  }, []);

  // Execute an action
  const executeAction = useCallback(
    (keyOrId: string): boolean => {
      const action = getAction(keyOrId);
      if (action) {
        action.execute(buffer);
        setLastAction(action);
        if (onTextChange) {
          onTextChange(buffer.getText());
        }
        return true;
      }
      return false;
    },
    [buffer, onTextChange]
  );

  // Buffer accessors
  const getText = useCallback(() => buffer.getText(), [buffer]);
  const setText = useCallback(
    (text: string) => {
      buffer.setText(text);
      if (onTextChange) {
        onTextChange(text);
      }
    },
    [buffer, onTextChange]
  );
  const getCursor = useCallback(() => buffer.getCursor(), [buffer]);
  const hasSelection = useCallback(
    () => buffer.getSelection() !== null,
    [buffer]
  );

  // Handle keyboard input
  useKeyboard((key) => {
    // Check for leader key activation
    if (key.ctrl && key.name === "space") {
      toggle();
      return;
    }

    // Help key works anytime (? requires shift on most keyboards)
    if (key.name === "?" && !key.ctrl && !key.meta) {
      toggleHelp();
      return;
    }

    // Only process if leader mode is active
    if (!isActive) return;

    // Escape to exit leader mode
    if (key.name === "escape") {
      deactivate();
      return;
    }

    // Build key sequence
    let keyStr = key.name || "";
    if (key.ctrl) keyStr = `ctrl+${keyStr}`;
    if (key.shift) keyStr = keyStr.toUpperCase();

    const newSequence = keySequence + keyStr;

    // Try to execute action with current sequence
    const action = getAction(newSequence);
    if (action) {
      action.execute(buffer);
      setLastAction(action);
      setKeySequence("");
      setIsActive(false);
      if (onTextChange) {
        onTextChange(buffer.getText());
      }
      return;
    }

    // Check if sequence could be a prefix of any action
    const couldMatch = allActions.some((a) => a.key.startsWith(newSequence));
    if (couldMatch) {
      setKeySequence(newSequence);
    } else {
      // No match possible, reset
      setKeySequence("");
      setIsActive(false);
    }
  });

  const value = useMemo<LeaderKeyContextValue>(
    () => ({
      isActive,
      keySequence,
      lastAction,
      showHelp,
      buffer,
      activate,
      deactivate,
      toggle,
      toggleHelp,
      executeAction,
      getText,
      setText,
      getCursor,
      hasSelection,
    }),
    [
      isActive,
      keySequence,
      lastAction,
      showHelp,
      buffer,
      activate,
      deactivate,
      toggle,
      toggleHelp,
      executeAction,
      getText,
      setText,
      getCursor,
      hasSelection,
    ]
  );

  return (
    <LeaderKeyContext.Provider value={value}>
      {children}
      {showHelp && <KeybindHelpOverlay onClose={toggleHelp} />}
      {isActive && <LeaderModeIndicator sequence={keySequence} />}
    </LeaderKeyContext.Provider>
  );
}

// ============================================
// Leader Mode Indicator
// ============================================

interface LeaderModeIndicatorProps {
  sequence: string;
}

function LeaderModeIndicator({ sequence }: LeaderModeIndicatorProps) {
  return (
    <box
      position="absolute"
      bottom={0}
      right={0}
      paddingLeft={1}
      paddingRight={1}
      backgroundColor={colors.backgroundDark}
    >
      <text fg={colors.yellowText}>
        LEADER{sequence ? `: ${sequence}` : ""}
      </text>
    </box>
  );
}

// ============================================
// Help Overlay
// ============================================

interface KeybindHelpOverlayProps {
  onClose: () => void;
}

function KeybindHelpOverlay({ onClose }: KeybindHelpOverlayProps) {
  const categories: ActionCategory[] = [
    "movement",
    "selection",
    "editing",
    "clipboard",
    "history",
  ];

  const categoryLabels: Record<ActionCategory, string> = {
    movement: "Movement",
    selection: "Selection",
    editing: "Editing",
    clipboard: "Clipboard",
    history: "History",
    misc: "Misc",
  };

  return (
    <box
      position="absolute"
      top={2}
      left={4}
      right={4}
      bottom={4}
      border={true}
      borderColor={colors.dimText}
      backgroundColor={colors.backgroundDarker}
      flexDirection="column"
      padding={2}
    >
      {/* Header */}
      <box flexDirection="row" justifyContent="space-between" marginBottom={1}>
        <text fg={colors.creamText}>Leader Key Shortcuts (Ctrl+Space)</text>
        <text fg={colors.dimText}>[?] to close</text>
      </box>

      {/* Categories */}
      <box flexDirection="row" flexWrap="wrap" gap={4}>
        {categories.map((category) => {
          const actions = allActions.filter((a) => a.category === category);
          if (actions.length === 0) return null;

          return (
            <box key={category} flexDirection="column" minWidth={20}>
              <text fg={colors.greenAccent}>{categoryLabels[category]}</text>
              {actions.slice(0, 8).map((action) => (
                <box key={action.id} flexDirection="row" gap={1}>
                  <text fg={colors.yellowText} minWidth={6}>
                    {action.key}
                  </text>
                  <text fg={colors.dimText}>{action.description}</text>
                </box>
              ))}
            </box>
          );
        })}
      </box>

      {/* Footer */}
      <box marginTop={2}>
        <text fg={colors.dimText}>
          Press Ctrl+Space to activate leader mode, then press a key sequence.
        </text>
      </box>
    </box>
  );
}

// ============================================
// Exports
// ============================================

export { InputBuffer } from "./input-buffer";
export { allActions, getAction, type Action, type ActionCategory } from "./actions";
