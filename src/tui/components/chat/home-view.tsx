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
import { OperatorModeBar, providerDisplayName } from "./input-area";
import { useTheme } from "../../theme";
import { useAgent } from "../../context/agent";
import * as History from "../../../core/history";

type ViewType = "home" | "config" | "chat";

interface HomeViewProps {
  onNavigate: (view: ViewType, options?: { sessionId?: string }) => void;
  onStartSession: (directive: string) => void;
}

export function HomeView({ onNavigate, onStartSession }: HomeViewProps) {
  const { colors } = useTheme();
  const { model } = useAgent();
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
      const requireApproval = options?.requireApproval ?? true;
      route.navigate({
        type: "operator",
        initialMessage: message,
        initialConfig: {
          requireApproval,
          operatorMode: requireApproval ? "manual" : "auto",
        },
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
      if (entry) {
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

  // Responsive layout calculations
  const height = dimensions.height;

  // Animation: scale down on small terminals, hide below 15 rows
  const animationHeight =
    height < 15
      ? 0
      : height < 20
        ? 2
        : height < 30
          ? Math.max(3, Math.floor(height * 0.15))
          : Math.max(6, Math.floor(height * 0.2));

  // Margins: reduce spacing on small terminals
  const titleMarginTop = height >= 20 ? 1 : 0;
  const menuMarginTop = height >= 25 ? 2 : height >= 15 ? 1 : 0;
  const inputMarginTop = height >= 25 ? 2 : height >= 15 ? 1 : 0;

  // Content visibility: hide decorative elements first
  const showCommands = height >= 22;
  const showHelpText = height >= 18;
  const inputPadding = height >= 20 ? 1 : 0;
  const inputWidth = Math.min(80, dimensions.width - 10);

  // Estimate rows consumed above the input to size the autocomplete dropdown
  const rowsAboveInput =
    animationHeight +
    titleMarginTop +
    2 + // title + subtitle
    (showCommands ? menuMarginTop + 5 : 0) +
    inputMarginTop +
    inputPadding + // top padding
    1; // input row itself
  const rowsBelowInput =
    (showHelpText ? 2 : 0) + // help text + marginTop
    inputPadding + // bottom padding
    3; // footer bar approximate
  const maxSuggestions = Math.max(2, height - rowsAboveInput - rowsBelowInput);

  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      alignItems="center"
      overflow="hidden"
    >
      {/* Petri Animation */}
      {animationHeight > 0 && (
        <box height={animationHeight} width="100%">
          <PetriAnimation height={animationHeight} />
        </box>
      )}

      {/* Title - centered */}
      <box
        flexDirection="column"
        alignItems="center"
        marginTop={titleMarginTop}
        flexShrink={0}
      >
        <text fg={colors.text}>
          Apex{" "}
          <span fg={colors.textMuted}>({config.data.version || "local"})</span>
        </text>
        <text fg={colors.textMuted}>Automated offensive security</text>
      </box>

      {/* Command Quick Reference */}
      {showCommands && (
        <box flexDirection="column" marginTop={menuMarginTop} flexShrink={0}>
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
      )}

      {/* Centered Input Area */}
      <box
        flexDirection="column"
        width={inputWidth}
        marginTop={inputMarginTop}
        padding={inputPadding}
        border={["left", "right"]}
        borderColor={colors.primary}
        flexShrink={0}
      >
        {/* Input with built-in autocomplete */}
        <PromptInput
          ref={promptRef}
          focused={!externalDialogOpen && stack.length === 0}
          width={inputWidth - 2 - inputPadding * 2}
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
          maxVisibleSuggestions={maxSuggestions}
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

        <OperatorModeBar
          operatorMode="manual"
          modelName={model.name}
          providerName={providerDisplayName(model.provider)}
          showMode={false}
          maxWidth={inputWidth - 2 - inputPadding * 2}
          rightContent={
            <text fg={colors.textMuted}>
              <span fg={colors.text}>[/]</span> commands
            </text>
          }
          rightContentWidth={"[/] commands".length}
        />
      </box>
    </box>
  );
}

export default HomeView;
