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
import { useRoute } from "../../context/route";
import { PromptInput } from "../shared/prompt-input";
import { useTheme } from "../../theme";
import { sessions, type SessionConfig } from "../../../core/session";
import { generateRandomName } from "../../../util/name";
import { slugify } from "../../../core/skills";

type ViewType = "home" | "config" | "chat";

interface HomeViewProps {
  onNavigate: (view: ViewType, options?: { sessionId?: string }) => void;
  onStartSession: (directive: string) => void;
}

export function HomeView({ onNavigate, onStartSession }: HomeViewProps) {
  const { colors } = useTheme();
  const dimensions = useTerminalDimensions();
  const config = useConfig();
  const route = useRoute();

  const { executeCommand, autocompleteOptions, resolveSkillContent, skills } =
    useCommand();
  const { setInputValue } = useInput();
  const { promptRef } = useFocus();

  const [hintMessage, setHintMessage] = useState<string | null>(null);
  const [isCreatingSession, setIsCreatingSession] = useState(false);

  const launchOperatorWithMessage = useCallback(
    async (
      message: string,
      options?: { requireApproval?: boolean },
    ) => {
      if (isCreatingSession) return;
      setIsCreatingSession(true);
      try {
        const sessionConfig: SessionConfig = {
          sessionType: "web-app",
          mode: "operator",
          operatorSettings: {
            initialMode: "auto",
            requireApproval: options?.requireApproval ?? true,
            enableSuggestions: true,
          },
        };
        const session = await sessions.create({
          targets: [],
          name: generateRandomName(),
          config: sessionConfig,
        });
        route.navigate({
          type: "operator",
          sessionId: session.id,
          initialMessage: message,
        });
      } catch {
        setHintMessage("Failed to create session");
        setIsCreatingSession(false);
      }
    },
    [isCreatingSession, route],
  );

  const handleSubmit = useCallback(
    (value: string) => {
      if (!value.trim()) return;
      launchOperatorWithMessage(value.trim());
    },
    [launchOperatorWithMessage],
  );

  // Auto-clear hint after 3 seconds
  useEffect(() => {
    if (!hintMessage) return;
    const timer = setTimeout(() => setHintMessage(null), 3000);
    return () => clearTimeout(timer);
  }, [hintMessage]);

  const handleCommandExecute = useCallback(
    async (command: string) => {
      // Split command into slug and args to detect --autopilot on skills
      const parts = command.trim().replace(/^\/+/, "").split(/\s+/);
      const slug = parts[0]?.toLowerCase() ?? "";
      const args = parts.slice(1);
      const autopilot = args.includes("--autopilot");

      const skillContent = resolveSkillContent(`/${slug}`);
      if (skillContent) {
        await launchOperatorWithMessage(skillContent, {
          requireApproval: !autopilot,
        });
        return;
      }
      await executeCommand(command);
    },
    [resolveSkillContent, launchOperatorWithMessage, executeCommand],
  );

  const skillItems = skills.slice(0, 5).map((s) => ({
    cmd: `/${slugify(s.name)}`,
    desc: s.description || "skill",
  }));

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
        {skillItems.length > 0 && (
          <>
            <box marginTop={1}>
              <box width={24} justifyContent="flex-end">
                <text fg={colors.textMuted}>Skills</text>
              </box>
            </box>
            {skillItems.map(({ cmd, desc }) => (
              <box key={cmd} flexDirection="row">
                <box width={24} justifyContent="flex-end">
                  <text fg={colors.accent}>{cmd}</text>
                </box>
                <box width={4} />
                <box>
                  <text fg={colors.textMuted}>{desc}</text>
                </box>
              </box>
            ))}
          </>
        )}
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
          placeholder={
            isCreatingSession
              ? "Starting operator session..."
              : "Type a message to start operator, or / for commands..."
          }
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
