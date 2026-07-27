/**
 * Home View
 *
 * Main entry screen with centered command input:
 * - Animated, terminal-responsive brand art
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
import { HomeGradientArt } from "./home-gradient-art";
import { getHomeLayout } from "./home-layout";
import { OperatorModeBar, providerDisplayName } from "./input-area";

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

  const layout = getHomeLayout(dimensions.width, dimensions.height);

  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      alignItems="center"
      overflow="hidden"
    >
      {layout.patternHeight > 0 && (
        <box
          position="absolute"
          top={0}
          left={0}
          height={layout.patternHeight}
          width="100%"
          overflow="hidden"
        >
          <HomeGradientArt height={layout.patternHeight} />
        </box>
      )}

      <box
        flexDirection="column"
        alignItems="center"
        justifyContent="center"
        height="100%"
      >
        <box
          flexDirection="column"
          alignItems="center"
          flexShrink={0}
          overflow="hidden"
        >
          <text fg={colors.text}>
            <span fg={colors.primary}>Apex</span>{" "}
            <span fg={colors.textMuted}>
              ({config.data.version || "local"})
            </span>
          </text>
          {layout.showSubtitle && (
            <text fg={colors.textMuted}>
              Autonomous security testing, from your terminal
            </text>
          )}
        </box>

        {layout.showWorkflowHints && (
          <box
            flexDirection="column"
            marginTop={layout.verticalGap}
            flexShrink={0}
          >
            {[
              { cmd: "/pentest", desc: "run an autonomous assessment" },
              { cmd: "/operator", desc: "direct the agent interactively" },
            ].map(({ cmd, desc }) => (
              <box key={cmd} flexDirection="row">
                <box width={12} justifyContent="flex-end">
                  <text fg={colors.primary}>{cmd}</text>
                </box>
                <box width={3} />
                <box>
                  <text fg={colors.textMuted}>{desc}</text>
                </box>
              </box>
            ))}
          </box>
        )}

        <box
          flexDirection="column"
          width={layout.inputWidth}
          marginTop={layout.verticalGap}
          padding={layout.inputPadding}
          border={["left", "right"]}
          borderColor={colors.primary}
          flexShrink={0}
          overflow="hidden"
        >
          <PromptInput
            ref={promptRef}
            focused={!externalDialogOpen && stack.length === 0}
            width={Math.max(1, layout.inputWidth - 2 - layout.inputPadding * 2)}
            minHeight={1}
            maxHeight={4}
            onSubmit={handleSubmit}
            placeholder="Describe a target or task, or type / for commands..."
            textColor={colors.text}
            focusedTextColor={colors.text}
            backgroundColor="transparent"
            focusedBackgroundColor="transparent"
            enableAutocomplete={true}
            autocompleteOptions={autocompleteOptions}
            commandOptionMap={commandOptionMap}
            commandNames={commandNames}
            maxVisibleSuggestions={layout.maxVisibleSuggestions}
            enableCommands={true}
            onCommandExecute={handleCommandExecute}
            commandHistory={commandHistory}
            showPromptIndicator={true}
          />

          <OperatorModeBar
            operatorMode="manual"
            modelName={model.name}
            providerName={providerDisplayName(model.provider)}
            showMode={false}
            maxWidth={Math.max(
              1,
              layout.inputWidth - 2 - layout.inputPadding * 2,
            )}
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
