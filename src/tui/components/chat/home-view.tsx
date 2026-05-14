/**
 * Home View
 *
 * Main entry screen with centered command input:
 * - Green ASCII petri animation
 * - Title and description
 * - Centered command input with inline autocomplete
 */

import { useCallback, useEffect, useState } from "react";
import * as History from "../../../core/history";
import { useAgent } from "../../context/agent";
import { useCommand } from "../../context/command";
import { useConfig } from "../../context/config";
import { useDialog } from "../../context/dialog";
import { useDimensions } from "../../context/dimensions";
import { useFocus } from "../../context/focus";
import { useInput } from "../../context/input";
import { useRoute } from "../../context/route";
import { useTheme } from "../../theme";
import { PromptInput } from "../shared";
import { OperatorModeBar, providerDisplayName } from "./input-area";
import { PetriAnimation } from "./petri-animation";

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

  const {
    executeCommand,
    autocompleteOptions,
    commandOptionMap,
    commandNames,
    skillsRegistry,
  } = useCommand();
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

      // Try the command registry first (handles arg parsing for registered commands)
      const handled = await executeCommand(command);
      if (handled) return;

      // Fallback: if the slug matches a skill, launch operator with that skill
      const slug =
        trimmed.replace(/^\/+/, "").split(/\s+/)[0]?.toLowerCase() ?? "";
      if (skillsRegistry.get(slug)) {
        route.navigate({
          type: "operator",
          nonce: Date.now(),
          initialConfig: { requireApproval: true },
          initialSkill: { slug },
        });
      }
    },
    [executeCommand, pushHistory, skillsRegistry, route],
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
  const inputPadding = height >= 20 ? 1 : 0;
  const inputWidth = Math.min(80, dimensions.width - 10);

  // Static content height (without the autocomplete dropdown) used to
  // compute a fixed top-margin anchor and size the dropdown window.
  // The petri animation is absolutely positioned and excluded from flow.
  const baseContentHeight =
    titleMarginTop +
    2 + // title + subtitle
    (showCommands ? menuMarginTop + 5 : 0) +
    inputMarginTop +
    inputPadding * 2 + // top + bottom padding of the input box
    2; // input row + operator mode bar

  const footerRows = 3;
  // Anchor the content block at a fixed vertical position so the input
  // doesn't drift when the dropdown opens or the textarea grows.
  const contentTopMargin = Math.max(
    0,
    Math.floor((height - footerRows - baseContentHeight) / 2),
  );

  // Available rows below the anchored content for the autocomplete dropdown.
  // Each suggestion item can occupy up to 2 terminal rows (label + wrapped
  // description), plus 3 rows of chrome (margin + scroll indicators).
  const rowsBelowContent =
    height - footerRows - contentTopMargin - baseContentHeight;
  const maxSuggestions = Math.max(
    2,
    Math.floor((rowsBelowContent - 3) / 2),
  );

  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      alignItems="center"
      overflow="hidden"
    >
      {/* Petri Animation - absolutely positioned so it doesn't push the
          centered content block off-center. Sits behind/above the column flow
          starting at the top of the home view. */}
      {animationHeight > 0 && (
        <box
          position="absolute"
          top={0}
          left={0}
          height={animationHeight}
          width="100%"
        >
          <PetriAnimation height={animationHeight} />
        </box>
      )}

      <box
        flexDirection="column"
        alignItems="center"
        marginTop={contentTopMargin}
      >
        {/* Title - centered */}
        <box
          flexDirection="column"
          alignItems="center"
          marginTop={titleMarginTop}
          flexShrink={0}
        >
          <text fg={colors.text}>
            Apex{" "}
            <span fg={colors.textMuted}>
              ({config.data.version || "local"})
            </span>
          </text>
          <text fg={colors.textMuted}>Automated offensive security</text>
        </box>

        {/* Command Quick Reference */}
        {showCommands && (
          <box flexDirection="column" marginTop={menuMarginTop} flexShrink={0}>
            {[
              { cmd: "/pentest", desc: "autonomous pentest" },
              { cmd: "/operator", desc: "interactive operator" },
              { cmd: "/login", desc: "login to Pensar" },
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
            commandOptionMap={commandOptionMap}
            commandNames={commandNames}
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
    </box>
  );
}
