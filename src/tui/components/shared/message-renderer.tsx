/**
 * Message Renderer Component
 *
 * Unified message display component for both operator and chat views.
 * Delegates to UserMessage, SystemMessage, AssistantMessage, or ToolRenderer.
 */

import { memo, useMemo } from "react";
import { useTheme } from "../../theme";
import { markdownToStyledText } from "./markdown";
import { ToolRenderer } from "./tool-renderer";
import { isToolMessage } from "./type-guards";
import type { DisplayMessage } from "../agent-display";
import { PlanReviewMessage } from "../chat/plan-review-message";
import { obfuscate } from "../../../core/obfuscation";
import { useObfuscation } from "../../context/obfuscation";

interface MessageRendererProps {
  message: DisplayMessage;
  isStreaming?: boolean;
  verbose?: boolean;
  expandedLogs?: boolean;
  /** Variant affects user message styling */
  variant?: "operator" | "chat";
  /** Optional username for chat variant */
  username?: string;
}

const SKILL_TAG_RE = /^<skill\s+name="([^"]+)"(?:\s+target="([^"]*)")?>/;

interface SkillTag {
  name: string;
  target?: string;
}

function parseSkillTag(content: string): SkillTag | null {
  const match = content.match(SKILL_TAG_RE);
  if (!match) return null;
  return { name: match[1], target: match[2] || undefined };
}

/**
 * Unified message renderer - delegates to role-specific components.
 */
export const MessageRenderer = memo(function MessageRenderer({
  message,
  isStreaming = false,
  verbose = false,
  expandedLogs = false,
  variant = "operator",
  username = "user",
}: MessageRendererProps) {
  const { colors } = useTheme();
  // Subscribe to obfuscation toggles so this component re-renders (and
  // re-runs `obfuscate()` / `markdownToStyledText()` with the new engine
  // state) when the operator toggles `/obfuscate` on or off.
  const { enabled: obfuscateEnabled } = useObfuscation();
  // Get string content
  const rawContent =
    typeof message.content === "string"
      ? message.content
      : JSON.stringify(message.content);
  // Assistant content gets obfuscated downstream by markdownToStyledText.
  // For all other roles we redact here so the same EMAIL_1 mapping is reused.
  const content =
    message.role === "assistant" ? rawContent : obfuscate(rawContent);

  // Memoize markdown conversion for assistant messages.
  // `obfuscateEnabled` is included in deps so toggling /obfuscate busts
  // the cache: the same rawContent must re-render with the new state.
  const displayContent = useMemo(
    () =>
      message.role === "assistant"
        ? markdownToStyledText(content, colors)
        : content,
    [content, message.role, colors, obfuscateEnabled],
  );

  // Tool messages
  if (isToolMessage(message)) {
    return (
      <ToolRenderer
        message={message}
        verbose={verbose}
        expandedLogs={expandedLogs}
      />
    );
  }

  // User messages — detect <skill name="..." target="..."> wrapper and display as /command.
  // Parse from the raw content because obfuscation turns the target into <URL_1>
  // which still satisfies the regex but we want to redact the target after the fact.
  if (message.role === "user") {
    const rawSkill = parseSkillTag(rawContent);
    const skill = rawSkill
      ? {
          name: rawSkill.name,
          target: rawSkill.target ? obfuscate(rawSkill.target) : undefined,
        }
      : null;

    if (variant === "chat") {
      return (
        <box flexDirection="column" marginTop={1}>
          <box flexDirection="row">
            <text fg={colors.secondary}>{"│ "}</text>
            {skill ? (
              <text fg={colors.primary}>
                /{skill.name}
                {skill.target ? (
                  <span fg={colors.textMuted}>{` ${skill.target}`}</span>
                ) : null}
              </text>
            ) : (
              <text fg={colors.text}>{content}</text>
            )}
          </box>
          <box marginLeft={2}>
            <text fg={colors.textMuted}>{username}</text>
          </box>
        </box>
      );
    }
    // Operator variant - simple prompt style
    return (
      <box flexDirection="row" gap={1} marginTop={1}>
        <text fg={colors.primary}>{">"}</text>
        {skill ? (
          <text fg={colors.primary}>
            /{skill.name}
            {skill.target ? (
              <span fg={colors.textMuted}>{` ${skill.target}`}</span>
            ) : null}
          </text>
        ) : (
          <text fg={colors.text}>{content}</text>
        )}
      </box>
    );
  }

  // Plan review messages
  if (message.isPlanReview && message.planContent) {
    return <PlanReviewMessage planContent={message.planContent} />;
  }

  // System messages
  if (message.role === "system") {
    return (
      <box marginTop={1} marginLeft={2}>
        <text fg={colors.textMuted}>{content}</text>
      </box>
    );
  }

  // Assistant messages
  if (variant === "chat") {
    // Chat variant - plain text, no bar
    return (
      <box flexDirection="column" marginTop={1}>
        <box flexDirection="column" marginLeft={0}>
          <text fg={colors.text} content={displayContent} />
          {isStreaming && !content.trim() && (
            <text fg={colors.textMuted}>...</text>
          )}
        </box>
      </box>
    );
  }

  // Operator variant - green left bar (Claude Code style)
  return (
    <box flexDirection="column" marginTop={1}>
      <box flexDirection="row">
        <text fg={colors.primary}>{"| "}</text>
        <box flexDirection="column" flexShrink={1}>
          <text fg={colors.text} content={displayContent} />
          {isStreaming && !content.trim() && (
            <text fg={colors.textMuted}>...</text>
          )}
        </box>
      </box>
    </box>
  );
});

export default MessageRenderer;
