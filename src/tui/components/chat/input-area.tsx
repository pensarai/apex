/**
 * Session Input Area Component
 *
 * Unified input component that handles:
 * - Normal directive input using shared PromptInput
 * - Approval mode input (redirect)
 * - Mode and status awareness
 */

import { useState, useEffect, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { useTheme, getTierColor } from "../../theme";
import { PromptInput, type PromptInputRef } from "../shared/prompt-input";
import { InputProvider, useInput } from "../../context/input";
import type { PendingApproval, OperatorMode } from "../../../core/operator";

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
  /** Operator mode (plan/manual/auto) */
  operatorMode?: OperatorMode;
  /** Verbose mode toggle */
  verboseMode?: boolean;
  /** Expanded logs toggle */
  expandedLogs?: boolean;
  /** Pending approval (transforms input area) */
  pendingApproval?: PendingApproval;
  /** Handler for approval */
  onApprove?: () => void;
  /** Handler for auto-approve */
  onAutoApprove?: () => void;
  /** Last decline note */
  lastDeclineNote?: string | null;
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
  verboseMode = false,
  expandedLogs = false,
}: Omit<
  InputAreaProps,
  "pendingApproval" | "onApprove" | "onAutoApprove" | "lastDeclineNote"
>) {
  const { colors } = useTheme();
  const { inputValue, setInputValue } = useInput();
  const promptRef = useRef<PromptInputRef>(null);
  const isExternalUpdate = useRef(false);

  const isDisabled = status === "running";

  // Sync external value prop to context when it changes
  useEffect(() => {
    if (value !== inputValue) {
      isExternalUpdate.current = true;
      setInputValue(value);
      promptRef.current?.setValue(value);
    }
  }, [value]);

  // Sync context changes back to parent via onChange
  useEffect(() => {
    if (isExternalUpdate.current) {
      isExternalUpdate.current = false;
      return;
    }
    if (inputValue !== value) {
      onChange(inputValue);
    }
  }, [inputValue]);

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
        <text fg={isDisabled ? colors.textMuted : colors.primary}>{">"}</text>
        <PromptInput
          ref={promptRef}
          width="100%"
          minHeight={1}
          maxHeight={3}
          textColor={colors.text}
          focused={focused && !isDisabled}
          placeholder={isDisabled ? "Processing..." : placeholder}
          onSubmit={handleSubmit}
        />
      </box>

      {/* Shortcuts row for operator mode */}
      {mode === "operator" && (
        <box
          flexDirection="row"
          gap={2}
          marginTop={1}
          backgroundColor="transparent"
        >
          {operatorMode === "plan" && (
            <text fg={colors.warning}>{"PLAN"}</text>
          )}
          {operatorMode === "auto" && (
            <text fg={colors.primary}>{"AUTO"}</text>
          )}
          {operatorMode === "manual" && (
            <text fg={colors.textMuted}>{"MANUAL"}</text>
          )}
          <text fg={verboseMode ? colors.primary : colors.textMuted}>
            {verboseMode ? "verbose:on" : "verbose"}
          </text>
          <text fg={expandedLogs ? colors.primary : colors.textMuted}>
            {expandedLogs ? "logs:full" : "logs"}
          </text>
          <text fg={colors.textMuted}>^C {value.trim() ? "clear" : "stop"}</text>
          <text fg={colors.textMuted}>ESC quit</text>
        </box>
      )}

      {/* Shortcuts row for chat mode */}
      {mode === "chat" && (
        <box
          flexDirection="row"
          gap={2}
          marginTop={1}
          backgroundColor="transparent"
        >
          <text fg={colors.textMuted}>^C {value.trim() ? "clear" : "stop"}</text>
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
  const tierColor = getTierColor(colors, approval.tier);

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
          content={`[A] Auto-approve T1-T${approval.tier} from now`}
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
          <text fg={colors.textMuted} content={`Declined: ${lastDeclineNote}`} />
        </box>
      )}

      {/* Shortcuts hint */}
      <box flexDirection="row" gap={2} marginTop={1}>
        <text fg={colors.textMuted} content="Y approve | A auto | Enter select" />
      </box>
    </box>
  );
}

export default InputArea;
