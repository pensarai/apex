/**
 * Home View
 *
 * Main entry screen with centered command input:
 * - Green ASCII petri animation
 * - Title and description
 * - Centered command input with inline autocomplete
 */

import { useCallback, useEffect, useState } from "react";
import { useTerminalDimensions } from "@opentui/react";
import { PetriAnimation } from "./petri-animation";
import { useCommand } from "../../context/command";
import { useInput } from "../../context/input";
import { useFocus } from "../../context/focus";
import { useConfig } from "../../context/config";
import { PromptInput } from "../shared/prompt-input";
import { useTheme } from "../../theme";

type ViewType = "home" | "config" | "chat";

interface HomeViewProps {
  onNavigate: (
    view: ViewType,
    options?: { sessionId?: string; isResume?: boolean },
  ) => void;
  onStartSession: (directive: string) => void;
}

export function HomeView({ onNavigate, onStartSession }: HomeViewProps) {
  const { colors } = useTheme();
  const dimensions = useTerminalDimensions();
  const config = useConfig();

  // Get autocomplete options and input sync from contexts
  const { executeCommand, autocompleteOptions } = useCommand();
  const { setInputValue } = useInput();
  const { promptRef } = useFocus();

  const [hintMessage, setHintMessage] = useState<string | null>(null);

  const handleSubmit = useCallback(
    (value: string) => {
      // Commands are handled by PromptInput; non-command text shows a hint
      setHintMessage("Type /help to get started");
      setInputValue("");
    },
    [setInputValue],
  );

  // Auto-clear hint after 3 seconds
  useEffect(() => {
    if (!hintMessage) return;
    const timer = setTimeout(() => setHintMessage(null), 3000);
    return () => clearTimeout(timer);
  }, [hintMessage]);

  const handleCommandExecute = useCallback(
    async (command: string) => {
      await executeCommand(command);
    },
    [executeCommand],
  );

  // Calculate layout dimensions
  const animationHeight = Math.max(6, Math.floor(dimensions.height * 0.2));
  const inputWidth = Math.min(80, dimensions.width - 10);

  return (
    <box flexDirection="column" width="100%" height="100%" alignItems="center">
      {/* Petri Animation */}
      <box height={animationHeight} width="100%">
        <PetriAnimation height={animationHeight} />
      </box>

      {/* Title - centered */}
      <box flexDirection="column" alignItems="center" marginTop={1}>
        <text fg={colors.text}>
          Apex{" "}
          <span fg={colors.textMuted}>({config.data.version || "local"})</span>
        </text>
        <text fg={colors.textMuted}>Automated offensive security</text>
      </box>

      {/* Command Quick Reference */}
      <box flexDirection="column" marginTop={2}>
        {[
          { cmd: "/pentest", desc: "autonomous pentest" },
          { cmd: "/operator", desc: "interactive operator" },
          { cmd: "/models", desc: "select AI model" },
          { cmd: "/providers", desc: "manage API keys" },
        ].map(({ cmd, desc }) => (
          <box key={cmd} flexDirection="row">
            <box width={14} justifyContent="flex-end">
              <text fg={colors.primary}>{cmd}</text>
            </box>
            <box width={4} />
            <box>
              <text fg={colors.textMuted}>{desc}</text>
            </box>
          </box>
        ))}
      </box>

      {/* Centered Input Area */}
      <box
        flexDirection="column"
        width={inputWidth}
        marginTop={2}
        padding={1}
        border={["left", "right"]}
        borderColor={colors.primary}
      >
        {/* Input with built-in autocomplete */}
        <PromptInput
          ref={promptRef}
          focused
          width={inputWidth - 4}
          minHeight={1}
          maxHeight={4}
          onSubmit={handleSubmit}
          placeholder="Type a command or message..."
          textColor={colors.text}
          focusedTextColor={colors.text}
          backgroundColor="transparent"
          focusedBackgroundColor="transparent"
          enableAutocomplete={true}
          autocompleteOptions={autocompleteOptions}
          enableCommands={true}
          onCommandExecute={handleCommandExecute}
          showPromptIndicator={true}
        />

        {/* Hint message */}
        {hintMessage && (
          <box marginTop={1}>
            <text fg={colors.text}>{hintMessage}</text>
          </box>
        )}

        {/* Help text */}
        <box marginTop={1}>
          <text fg={colors.textMuted}>
            <span>Type </span>
            <span fg={colors.text}>/</span>
            <span> for commands</span>
            <span> • </span>
            <span fg={colors.text}>[↓][↑]</span>
            <span> navigate</span>
            <span> • </span>
            <span fg={colors.text}>[tab]</span>
            <span> complete</span>
            <span> • </span>
            <span fg={colors.text}>[enter]</span>
            <span> run</span>
          </text>
        </box>
      </box>
    </box>
  );
}
