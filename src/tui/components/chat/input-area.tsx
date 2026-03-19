/**
 * Session Input Area Component
 *
 * Unified input component that handles:
 * - Normal directive input using shared PromptInput
 * - Approval mode input (redirect)
 * - Mode and status awareness
 */

import React, { useState, useEffect, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { useTheme } from "../../theme";
import { PromptInput, type PromptInputRef } from "../shared/prompt-input";
import { InputProvider, useInput } from "../../context/input";
import type { PendingApproval } from "../../../core/operator";
import {
  type OperatorMode,
  OPERATOR_MODES,
} from "../../../core/operator";
import { useAgent } from "../../context/agent";
import { useDimensions } from "../../context/dimensions";

const PROVIDER_DISPLAY_NAMES: Record<string, string> = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  google: "Google",
  openrouter: "OpenRouter",
  bedrock: "Bedrock",
  pensar: "Pensar",
  inception: "Inception",
  local: "Local",
};
export const providerDisplayName = (p: string) => PROVIDER_DISPLAY_NAMES[p] ?? p;

export interface InputAreaProps {
  /** Current input value */
  value: string;
  /** Input change handler */
  onChange: (value: string) => void;
  /** Submit handler */
  onSubmit: (value: string) => void;
  /** Input placeholder */
  placeholder?: string;
  /** Whether input is focused */
  focused?: boolean;
  /** Current status */
  status: "idle" | "running" | "waiting" | "done";
  /** Display mode */
  mode?: "chat" | "operator";
  /** Operator mode (approvals-on/approvals-off/plan) */
  operatorMode?: OperatorMode;
  /** Pending approval (transforms input area) */
  pendingApproval?: PendingApproval;
  /** Handler for approval */
  onApprove?: () => void;
  /** Handler for auto-approve */
  onAutoApprove?: () => void;
  /** Last decline note */
  lastDeclineNote?: string | null;
  /** Enable autocomplete suggestions (e.g. slash commands, skills) */
  enableAutocomplete?: boolean;
  /** Autocomplete options to show */
  autocompleteOptions?: import("../shared/prompt-input").AutocompleteOption[];
  /** Enable slash-command handling */
  enableCommands?: boolean;
  /** Handler for slash-command execution */
  onCommandExecute?: (command: string) => Promise<void>;
  /** Command history for up/down arrow navigation */
  commandHistory?: string[];
  /** Suppress Up/Down history navigation in PromptInput (e.g. queue takes priority) */
  disableHistoryNavigation?: boolean;
  /** Whether autocomplete suggestions appear above or below the input */
  autocompletePlacement?: "above" | "below";
  /** Highlight /slash-command patterns in the input text */
  highlightSlashCommands?: boolean;
}

/**
 * Responsive operator mode bar.
 *
 * Collapse order (widest → narrowest):
 *   mode  (shift+tab to cycle)  model  provider  [rightContent]
 *   mode  (shift+tab)           model  provider  [rightContent]
 *   mode  (shift+tab)           model  provider
 *   mode  (shift+tab)           model
 *   mode                        model
 */
export function OperatorModeBar({
  operatorMode,
  modelName,
  providerName,
  showMode = true,
  showCycleHint = true,
  maxWidth,
  rightContent,
  rightContentWidth = 0,
}: {
  operatorMode: OperatorMode;
  modelName: string;
  providerName: string;
  /** Show the mode badge. Set false to show only model/provider. */
  showMode?: boolean;
  showCycleHint?: boolean;
  maxWidth?: number;
  rightContent?: React.ReactNode;
  /** Character width of rightContent for collapse calculations. */
  rightContentWidth?: number;
}) {
  const { colors } = useTheme();
  const { width: termWidth } = useDimensions();
  const w = maxWidth ?? termWidth - 4;

  const modeConfig = OPERATOR_MODES[operatorMode];
  const modeText = `${modeConfig.icon} ${modeConfig.label}`;
  const cycleLong = "(shift+tab to cycle)";
  const cycleShort = "(shift+tab)";
  const g = 2; // gap between items

  const mL = showMode ? modeText.length : 0;
  const moL = modelName.length;
  const pL = providerName.length;
  const rL = rightContentWidth;

  // Always present: model (+ mode if shown)
  const base = showMode ? mL + g + moL : moL;

  // Build up from base, checking what fits
  const canCycleLong =
    showMode && showCycleHint && base + g + cycleLong.length <= w;
  const canCycleShort =
    showMode && showCycleHint && !canCycleLong && base + g + cycleShort.length <= w;
  const cycleLen = canCycleLong
    ? cycleLong.length
    : canCycleShort
      ? cycleShort.length
      : 0;
  const withCycle = cycleLen > 0 ? base + g + cycleLen : base;

  const canProvider = withCycle + g + pL <= w;
  const withProvider = canProvider ? withCycle + g + pL : withCycle;

  const canRight = rL > 0 && withProvider + g + rL <= w;

  const cycleDisplay = canCycleLong
    ? cycleLong
    : canCycleShort
      ? cycleShort
      : null;

  return (
    <box
      flexDirection="row"
      justifyContent={canRight ? "space-between" : "flex-start"}
      marginTop={1}
      backgroundColor="transparent"
      alignItems="center"
      overflow="hidden"
    >
      <box flexDirection="row" gap={2} alignItems="center">
        {showMode && (
          <text fg={colors[modeConfig.colorKey as keyof typeof colors]}>
            {modeText}
          </text>
        )}
        {cycleDisplay && (
          <text fg={colors.textMuted}>{cycleDisplay}</text>
        )}
        <text fg={colors.text}>{modelName}</text>
        {canProvider && (
          <text fg={colors.textMuted}>{providerName}</text>
        )}
      </box>
      {canRight && rightContent}
    </box>
  );
}

/**
 * Inner component that syncs external value/onChange with InputContext
 * Only used for normal (non-approval) input mode
 */
function NormalInputAreaInner({
  value,
  onChange,
  onSubmit,
  placeholder = "Enter directive...",
  focused = true,
  status,
  mode = "operator",
  operatorMode,
  enableAutocomplete = false,
  autocompleteOptions = [],
  enableCommands = false,
  onCommandExecute,
  commandHistory = [],
  disableHistoryNavigation = false,
  autocompletePlacement = "below",
  highlightSlashCommands = false,
}: Omit<
  InputAreaProps,
  "pendingApproval" | "onApprove" | "onAutoApprove" | "lastDeclineNote"
>) {
  const { colors, theme, mode: colorMode } = useTheme();
  const { model } = useAgent();
  const { inputValue, setInputValue } = useInput();
  const promptRef = useRef<PromptInputRef>(null);
  const isExternalUpdate = useRef(false);
  const prevValueRef = useRef(value);

  // Sync external value prop to context when the parent explicitly changes it.
  // Only sync when the value prop itself changed between renders (not just a
  // re-render with stale value), to avoid resetting user input during typing.
  useEffect(() => {
    const prevValue = prevValueRef.current;
    prevValueRef.current = value;

    // Only sync if the parent's value prop actually changed from the previous render
    if (value !== prevValue && value !== inputValue) {
      isExternalUpdate.current = true;
      setInputValue(value);
      promptRef.current?.setValue(value);
    }
  }, [value, inputValue, setInputValue]);

  // Sync context changes back to parent via onChange
  useEffect(() => {
    if (isExternalUpdate.current) {
      isExternalUpdate.current = false;
      return;
    }
    if (inputValue !== value) {
      onChange(inputValue);
    }
  }, [inputValue, value, onChange]);

  const handleSubmit = (val: string) => {
    if (val.trim()) {
      onSubmit(val.trim());
    }
  };

  return (
    <box
      flexDirection="column"
      flexShrink={0}
      paddingLeft={2}
      paddingRight={2}
      paddingTop={1}
      paddingBottom={1}
      backgroundColor="transparent"
    >
      <box flexDirection="row" gap={1} backgroundColor="transparent">
        <text fg={!focused ? colors.textMuted : colors.primary}>{">"}</text>
        <PromptInput
          key={`${theme.name}-${colorMode}`}
          ref={promptRef}
          width="100%"
          minHeight={1}
          maxHeight={3}
          textColor={colors.text}
          focused={focused}
          placeholder={placeholder}
          onSubmit={handleSubmit}
          enableAutocomplete={enableAutocomplete}
          autocompleteOptions={autocompleteOptions}
          enableCommands={enableCommands}
          onCommandExecute={onCommandExecute}
          commandHistory={commandHistory}
          disableHistoryNavigation={disableHistoryNavigation}
          autocompletePlacement={autocompletePlacement}
          highlightSlashCommands={highlightSlashCommands}
        />
      </box>

      {/* Mode + model for operator mode */}
      {mode === "operator" && operatorMode && (
        <OperatorModeBar
          operatorMode={operatorMode}
          modelName={model.name}
          providerName={providerDisplayName(model.provider)}
        />
      )}

      {/* Shortcuts row for chat mode */}
      {mode === "chat" && (
        <box
          flexDirection="row"
          gap={2}
          marginTop={1}
          backgroundColor="transparent"
        >
          <text fg={colors.textMuted}>
            ^C {value.trim() ? "clear" : "stop"}
          </text>
          <text fg={colors.textMuted}>^B sidebar</text>
          <text fg={colors.textMuted}>ESC quit</text>
        </box>
      )}
    </box>
  );
}

/**
 * Session input area - handles both normal and approval modes
 * Approval mode bypasses InputProvider since it has its own focus management
 */
export function InputArea(props: InputAreaProps) {
  const {
    pendingApproval,
    onApprove,
    onAutoApprove,
    lastDeclineNote,
    value,
    onChange,
    onSubmit,
    enableAutocomplete,
    autocompleteOptions,
    enableCommands,
    onCommandExecute,
    commandHistory,
    disableHistoryNavigation,
    autocompletePlacement,
    ...normalProps
  } = props;

  // Approval mode - render without InputProvider
  if (pendingApproval) {
    return (
      <ApprovalInputArea
        approval={pendingApproval}
        onApprove={onApprove || (() => {})}
        onAutoApprove={onAutoApprove || (() => {})}
        onRedirect={onSubmit}
        redirectInput={value}
        setRedirectInput={onChange}
        lastDeclineNote={lastDeclineNote}
      />
    );
  }

  // Normal mode - wrap with InputProvider
  return (
    <InputProvider>
      <NormalInputAreaInner
        value={value}
        onChange={onChange}
        onSubmit={onSubmit}
        enableAutocomplete={enableAutocomplete}
        autocompleteOptions={autocompleteOptions}
        enableCommands={enableCommands}
        onCommandExecute={onCommandExecute}
        commandHistory={commandHistory}
        disableHistoryNavigation={disableHistoryNavigation}
        autocompletePlacement={autocompletePlacement}
        {...normalProps}
      />
    </InputProvider>
  );
}

/**
 * Approval input area - shown when there's a pending approval
 */
interface ApprovalInputAreaProps {
  approval: PendingApproval;
  onApprove: () => void;
  onAutoApprove: () => void;
  onRedirect: (message: string) => void;
  redirectInput: string;
  setRedirectInput: (value: string) => void;
  lastDeclineNote?: string | null;
}

function ApprovalInputArea({
  approval,
  onApprove,
  onAutoApprove,
  onRedirect,
  redirectInput,
  setRedirectInput,
  lastDeclineNote,
}: ApprovalInputAreaProps) {
  const { colors } = useTheme();
  const [focusedElement, setFocusedElement] = useState(0); // 0=Yes, 1=Auto, 2=Input

  useKeyboard((key) => {
    // Navigation
    if (key.name === "up") {
      setFocusedElement((prev) => Math.max(0, prev - 1));
      return;
    }
    if (key.name === "down" || (key.name === "tab" && !key.shift)) {
      setFocusedElement((prev) => Math.min(2, prev + 1));
      return;
    }
    if (key.name === "tab" && key.shift) {
      setFocusedElement((prev) => Math.max(0, prev - 1));
      return;
    }

    // Enter to select
    if (key.name === "return") {
      if (focusedElement === 0) {
        onApprove();
      } else if (focusedElement === 1) {
        onAutoApprove();
      } else if (focusedElement === 2 && redirectInput.trim()) {
        onRedirect(redirectInput);
      }
      return;
    }
  });

  return (
    <box
      flexDirection="column"
      flexShrink={0}
      paddingLeft={2}
      paddingRight={2}
      paddingTop={1}
      paddingBottom={1}
    >
      {/* Yes option */}
      <box flexDirection="row" gap={1}>
        <text
          fg={focusedElement === 0 ? colors.primary : colors.textMuted}
          content={focusedElement === 0 ? ">" : " "}
        />
        <text
          fg={focusedElement === 0 ? colors.text : colors.textMuted}
          content="[Y] Approve this action"
        />
      </box>

      {/* Auto option */}
      <box flexDirection="row" gap={1}>
        <text
          fg={focusedElement === 1 ? colors.warning : colors.textMuted}
          content={focusedElement === 1 ? ">" : " "}
        />
        <text
          fg={focusedElement === 1 ? colors.text : colors.textMuted}
          content="[A] Auto-approve all commands from now"
        />
      </box>

      {/* Redirect input */}
      <box flexDirection="row" gap={1} marginTop={1}>
        <text
          fg={focusedElement === 2 ? colors.primary : colors.textMuted}
          content={focusedElement === 2 ? ">" : " "}
        />
        <text fg={colors.primary} content=">" />
        <input
          width="100%"
          value={redirectInput}
          onInput={setRedirectInput}
          onPaste={(event) => {
            const cleaned = String(event.text).replace(/\r?\n/g, " ");
            setRedirectInput(cleaned);
          }}
          focused={focusedElement === 2}
          placeholder="Or type to redirect agent..."
          textColor={colors.text}
          backgroundColor="transparent"
          cursorColor={colors.textMuted}
        />
      </box>

      {/* Last decline note */}
      {lastDeclineNote && (
        <box marginTop={1} marginLeft={2}>
          <text
            fg={colors.textMuted}
            content={`Declined: ${lastDeclineNote}`}
          />
        </box>
      )}

      {/* Shortcuts hint */}
      <box flexDirection="row" gap={2} marginTop={1}>
        <text
          fg={colors.textMuted}
          content="Y approve | A auto | Enter select"
        />
      </box>
    </box>
  );
}

export default InputArea;
