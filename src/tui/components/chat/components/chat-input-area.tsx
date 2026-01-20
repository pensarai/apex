/**
 * Chat Input Area Component
 *
 * Simple input area for the chat view with status indicator.
 * Uses the shared PromptInput component with InputContext.
 */

import { useEffect, useRef } from "react";
import { RGBA } from "@opentui/core";
import { PromptInput, type PromptInputRef } from "../../shared/prompt-input";
import { InputProvider, useInput } from "../../../context/input";

// Colors
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

export type ChatStatus = "idle" | "running" | "waiting" | "done";

export interface ChatInputAreaProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: (value: string) => void;
  placeholder?: string;
  focused?: boolean;
  status: ChatStatus;
}

/**
 * Inner component that syncs external value/onChange with InputContext
 */
function ChatInputAreaInner({
  value,
  onChange,
  onSubmit,
  placeholder = "Enter directive...",
  focused = true,
  status,
}: ChatInputAreaProps) {
  const { inputValue, setInputValue } = useInput();
  const promptRef = useRef<PromptInputRef>(null);
  const isExternalUpdate = useRef(false);

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

  const isDisabled = status === "running";

  return (
    <box
      width="100%"
      flexDirection="row"
      alignItems="center"
      paddingLeft={1}
      paddingRight={1}
    >
      {/* Prompt indicator */}
      <text fg={isDisabled ? dimText : greenAccent}>
        <span>{"❯ "}</span>
      </text>

      {/* Input field */}
      <PromptInput
        ref={promptRef}
        width="100%"
        minHeight={1}
        maxHeight={3}
        focused={focused && !isDisabled}
        placeholder={isDisabled ? "Processing..." : placeholder}
        onSubmit={handleSubmit}
      />
    </box>
  );
}

export function ChatInputArea(props: ChatInputAreaProps) {
  return (
    <InputProvider>
      <ChatInputAreaInner {...props} />
    </InputProvider>
  );
}

export default ChatInputArea;
