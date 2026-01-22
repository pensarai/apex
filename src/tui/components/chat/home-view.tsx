/**
 * Home View
 *
 * Main entry screen with centered command input:
 * - Green ASCII petri animation
 * - Title and description
 * - Centered command input with inline autocomplete
 */

import { useCallback } from "react";
import { RGBA } from "@opentui/core";
import { useTerminalDimensions } from "@opentui/react";
import { PetriAnimation } from "./petri-animation";
import { useCommand } from "../../context/command";
import { useInput } from "../../context/input";
import { useFocus } from "../../context/focus";
import { useConfig } from "../../context/config";
import { PromptInput } from "../shared/prompt-input";

// Colors
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

type ViewType = "home" | "config" | "chat";

interface HomeViewProps {
  onNavigate: (view: ViewType, options?: { sessionId?: string; isResume?: boolean }) => void;
  onStartSession: (directive: string) => void;
}

export function HomeView({ onNavigate, onStartSession }: HomeViewProps) {
  const dimensions = useTerminalDimensions();
  const config = useConfig();

  // Get autocomplete options and input sync from contexts
  const { executeCommand, autocompleteOptions } = useCommand();
  const { setInputValue } = useInput();
  const { promptRef } = useFocus();

  const handleSubmit = useCallback((value: string) => {
    // Commands are handled by PromptInput, this only gets non-command text
    onStartSession(value);
    setInputValue("");
  }, [onStartSession, setInputValue]);

  const handleCommandExecute = useCallback(async (command: string) => {
    await executeCommand(command);
  }, [executeCommand]);

  // Calculate layout dimensions
  const animationHeight = Math.max(6, Math.floor(dimensions.height * 0.2));
  const inputWidth = Math.min(80, dimensions.width - 10);

  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      alignItems="center"
    >
      {/* Petri Animation */}
      <box height={animationHeight} width="100%">
        <PetriAnimation height={animationHeight} />
      </box>

      {/* Title - centered */}
      <box flexDirection="column" alignItems="center" marginTop={1}>
        <text fg={creamText}>
          Apex <span fg={dimText}>({config.data.version || "local"})</span>
        </text>
        <text fg={dimText}>Automated offensive security</text>
      </box>

      {/* Centered Input Area */}
      <box
        flexDirection="column"
        width={inputWidth}
        marginTop={8}
        padding={1}
        border={['left', 'right']}
        borderColor={greenAccent}
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
          textColor="white"
          focusedTextColor="white"
          backgroundColor="transparent"
          focusedBackgroundColor="transparent"
          enableAutocomplete={true}
          autocompleteOptions={autocompleteOptions}
          enableCommands={true}
          onCommandExecute={handleCommandExecute}
          showPromptIndicator={true}
        />

        {/* Help text */}
        <box marginTop={1}>
          <text fg={dimText}>
            <span>Type </span>
            <span fg={creamText}>/</span>
            <span> for commands</span>
            <span>  •  </span>
            <span fg={creamText}>[↓][↑]</span>
            <span> navigate</span>
            <span>  •  </span>
            <span fg={creamText}>[tab]</span>
            <span> complete</span>
            <span>  •  </span>
            <span fg={creamText}>[enter]</span>
            <span> run</span>
          </text>
        </box>
      </box>
    </box>
  );
}

export default HomeView;
