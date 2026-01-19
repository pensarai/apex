/**
 * Chat Input Area Component
 *
 * Simple input area for the chat view with status indicator.
 */

import { RGBA } from "@opentui/core";
import Input from "../../../components/input";

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

export function ChatInputArea({
  value,
  onChange,
  onSubmit,
  placeholder = "Enter directive...",
  focused = true,
  status,
}: ChatInputAreaProps) {
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
      <Input
        label=""
        value={value}
        onInput={onChange}
        onSubmit={handleSubmit}
        focused={focused && !isDisabled}
        placeholder={isDisabled ? "Processing..." : placeholder}
      />
    </box>
  );
}

export default ChatInputArea;
