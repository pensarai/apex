/**
 * Home View
 *
 * Main entry screen with centered command input:
 * - Green ASCII petri animation
 * - Title and description
 * - Centered command input with inline autocomplete
 */

import { useCallback, useEffect, useState } from "react";
import { useDimensions } from "../../context/dimensions";
import { PetriAnimation } from "./petri-animation";
import { useCommand } from "../../context/command";
import { useInput } from "../../context/input";
import { useFocus } from "../../context/focus";
import { useConfig } from "../../context/config";
import { useRoute } from "../../context/route";
import { useDialog } from "../../context/dialog";
import { PromptInput } from "../shared/prompt-input";
import { useTheme } from "../../theme";
import * as History from "../../../core/history";

type ViewType = "home" | "config" | "chat";

interface HomeViewProps {
  onNavigate: (view: ViewType, options?: { sessionId?: string }) => void;
  onStartSession: (directive: string) => void;
}

export function HomeView({ onNavigate, onStartSession }: HomeViewProps) {
  const { colors } = useTheme();
  const dimensions = useDimensions();
  const config = useConfig();
  const route = useRoute();

  const { executeCommand, autocompleteOptions, skillsRegistry } = useCommand();
  const { setInputValue } = useInput();
  const { promptRef } = useFocus();
  const { externalDialogOpen, stack } = useDialog();

  const [hintMessage, setHintMessage] = useState<string | null>(null);
  const [commandHistory, setCommandHistory] = useState<string[]>(
    History.getEntries,
  );

  useEffect(() => {
    History.load().then(setCommandHistory);
  }, []);

  const launchOperator = useCallback(
    (message: string, options?: { requireApproval?: boolean }) => {
      route.navigate({
        type: "operator",
        initialMessage: message,
        initialConfig: { requireApproval: options?.requireApproval ?? true },
      });
    },
    [route],
  );

  const pushHistory = useCallback((entry: string) => {
    History.push(entry).then(() =>
      setCommandHistory([...History.getEntries()]),
    );
  }, []);

  const handleSubmit = useCallback(
    (value: string) => {
      if (!value.trim()) return;
      pushHistory(value.trim());
      launchOperator(value.trim());
    },
    [launchOperator, pushHistory],
  );

  // Auto-clear hint after 3 seconds
  useEffect(() => {
    if (!hintMessage) return;
    const timer = setTimeout(() => setHintMessage(null), 3000);
    return () => clearTimeout(timer);
  }, [hintMessage]);

  const handleCommandExecute = useCallback(
    async (command: string) => {
      const trimmed = command.trim();
      pushHistory(trimmed);

      const slug =
        trimmed.replace(/^\/+/, "").split(/\s+/)[0]?.toLowerCase() ?? "";

      const entry = skillsRegistry.get(slug);
      if (entry?.enabled) {
        // Navigate to skills detail page to show skill info
        route.navigate({
          type: "base",
          path: "skills",
          options: { skillSlug: slug },
        });
        return;
      }
      await executeCommand(command);
    },
    [skillsRegistry, route, executeCommand, pushHistory],
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
          { cmd: "/auth", desc: "login to Pensar" },
          { cmd: "/models", desc: "select AI model" },
          { cmd: "/providers", desc: "manage API keys" },
        ].map(({ cmd, desc }) => (
          <box key={cmd} flexDirection="row">
            <box width={24} justifyContent="flex-end">
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
          focused={!externalDialogOpen && stack.length === 0}
          width={inputWidth - 4}
          minHeight={1}
          maxHeight={4}
          onSubmit={handleSubmit}
          placeholder="Type a message to start operator, or / for commands..."
          textColor={colors.text}
          focusedTextColor={colors.text}
          backgroundColor="transparent"
          focusedBackgroundColor="transparent"
          enableAutocomplete={true}
          autocompleteOptions={autocompleteOptions}
          enableCommands={true}
          onCommandExecute={handleCommandExecute}
          commandHistory={commandHistory}
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
            <span fg={colors.text}>[enter]</span>
            <span> open operator</span>
            <span> • </span>
            <span fg={colors.text}>/</span>
            <span> commands</span>
            <span> • </span>
            <span fg={colors.text}>[↓][↑]</span>
            <span> navigate</span>
            <span> • </span>
            <span fg={colors.text}>[tab]</span>
            <span> complete</span>
          </text>
        </box>
      </box>
    </box>
  );
}

export default HomeView;
