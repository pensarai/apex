import {
  RGBA,
  StyledText,
} from "@opentui/core";
import { SpinnerDots } from "./sprites";
import { useState, memo } from "react";
import type { Message } from "../../core/messages/types";
import { useTerminalDimensions } from "@opentui/react";
import { markdownToStyledText, getStableMessageKey, getArgsPreview } from "./shared";

export type Subagent = {
  id: string;
  name: string;
  type: "attack-surface" | "pentest";
  target: string;
  messages: Message[];
  createdAt: Date;
  status: "pending" | "completed" | "failed";
};

/**
 * Tool execution status.
 */
export type ToolStatus = "pending" | "completed" | "error";

/**
 * Display message type - flexible type for UI display.
 *
 * For tool messages: toolCallId, toolName, args, and status are required.
 * For text messages: only role, content, and createdAt are required.
 *
 * Use isToolMessage() type guard for safe narrowing to tool messages.
 */
export type DisplayMessage = {
  role: "user" | "assistant" | "system" | "tool";
  content: string | unknown[];
  createdAt: Date;
  // Tool-specific fields (present when role === "tool")
  toolCallId?: string;
  toolName?: string;
  args?: Record<string, unknown>;
  result?: unknown;
  status?: ToolStatus;
  logs?: string[];
};

function getStableKey(
  item: DisplayMessage | Subagent,
  contextId: string = "root"
): string {
  // Subagents have their own unique ID
  if ("messages" in item) {
    return `subagent-${item.id}`;
  }
  // Use shared utility for display messages
  return getStableMessageKey(item, contextId);
}

interface AgentDisplayProps {
  messages: DisplayMessage[];
  isStreaming?: boolean;
  children?: React.ReactNode;
  subagents?: Subagent[];
  paddingLeft?: number;
  paddingRight?: number;
  contextId?: string; // Used to ensure unique keys across nested displays
  focused?: boolean; // Controls whether this scrollbox responds to scroll events
}


export default function AgentDisplay({
  messages,
  isStreaming = false,
  children,
  subagents,
  paddingLeft = 8,
  paddingRight = 8,
  contextId = "root",
  focused = true,
}: AgentDisplayProps) {
  // Sort messages and subagents by creation time
  // Don't use useMemo to ensure we always have fresh data during rapid updates
  const messagesAndSubagents = [...messages, ...(subagents ?? [])].sort(
    (a, b) => a.createdAt.getTime() - b.createdAt.getTime()
  );

  return (
    <scrollbox
      style={{
        rootOptions: {
          width: "100%",
          maxWidth: "100%",
          flexGrow: 1,
          flexShrink: 1,
        },
        contentOptions: {
          paddingLeft: paddingLeft,
          paddingRight: paddingRight,
          gap: 1,
          flexDirection: "column",
        },
        scrollbarOptions: {
          trackOptions: {
            foregroundColor: "green",
            backgroundColor: RGBA.fromInts(40, 40, 40, 255),
          },
        },
      }}
      stickyScroll={true}
      stickyStart="bottom"
      focused={focused}
      onMouseScroll={
        !focused
          ? (event: any) => {
              // Stop scroll events from propagating to parent scrollbox
              event.stopPropagation();
            }
          : undefined
      }
    >
      {messagesAndSubagents.map((item) => {
        // Get stable unique key for this item, using contextId to prevent collisions
        const itemKey = getStableKey(item, contextId);

        if ("messages" in item) {
          return (
            <box key={itemKey}>
              <SubAgentDisplay subagent={item} />
            </box>
          );
        } else {
          return (
            <box key={itemKey}>
              <AgentMessage message={item} />
            </box>
          );
        }
      })}

      {isStreaming && (
        <box flexDirection="row" alignItems="center">
          <SpinnerDots label="Thinking..." fg="green" />
        </box>
      )}

      {children}
    </scrollbox>
  );
}

const SubAgentDisplay = memo(function SubAgentDisplay({
  subagent,
}: {
  subagent: Subagent;
}) {
  const [open, setOpen] = useState(false);

  return (
    <box
      height={open ? 40 : "auto"}
      onMouseDown={() => setOpen(!open)}
      width="100%"
      border={true}
      borderColor="green"
      backgroundColor={RGBA.fromInts(10, 10, 10, 255)}
    >
      <box flexDirection="row" alignItems="center" gap={1}>
        {subagent.status === "pending" && (
          <SpinnerDots label={subagent.name} fg="green" />
        )}
        {subagent.status === "completed" && (
          <text fg="green"> ✓ {subagent.name}</text>
        )}
        {subagent.status === "failed" && (
          <text fg="red">✗ {subagent.name}</text>
        )}
        <text fg="gray">{open ? "▼" : "▶"}</text>
      </box>
      {open && (
        <AgentDisplay
          paddingLeft={2}
          paddingRight={2}
          messages={subagent.messages}
          contextId={subagent.id}
          focused={false}
        />
      )}
    </box>
  );
});

const AgentMessage = memo(function AgentMessage({
  message,
}: {
  message: DisplayMessage;
}) {
  const dimensions = useTerminalDimensions();
  let content = "";

  if (typeof message.content === "string") {
    content = message.content;
  } else if (Array.isArray(message.content)) {
    // Handle array of content parts
    content = message.content
      .map((part: any) => {
        if (typeof part === "string") return part;
        if (part.type === "text") return part.text;
        return JSON.stringify(part);
      })
      .join("");
  } else {
    content = JSON.stringify(message.content, null, 2);
  }

  // Render markdown for assistant messages
  const displayContent =
    message.role === "assistant" ? markdownToStyledText(content) : content;

  // Check if this is a pending tool message
  const isPendingTool =
    message.role === "tool" && message.status === "pending";
  const isCompletedTool =
    message.role === "tool" && message.status === "completed";
  const isErrorTool =
    message.role === "tool" && message.status === "error";

  // Get args preview for tool messages
  const argsPreview =
    message.role === "tool" && message.args
      ? getArgsPreview(message.toolName || "", message.args, 80)
      : "";

  // Get streaming logs for pending tools
  const streamingLogs = message.logs || [];

  return (
    <box
      flexDirection="column"
      width="100%"
      gap={1}
      alignItems={message.role === "user" ? "flex-end" : "flex-start"}
    >
      {message.role !== "tool" && (
        <text
          fg="green"
          content={message.role === "user" ? "→ User" : "← Assistant"}
        />
      )}
      <box flexDirection="row" gap={0}>
        {message.role === "assistant" && (
          <box
            width={0}
            borderStyle="heavy"
            border={["right"]}
            borderColor={RGBA.fromInts(30, 30, 30, 255)}
          />
        )}
        <box
          maxWidth={dimensions.width - 20}
          padding={message.role !== "tool" ? 1 : 0}
          backgroundColor={
            message.role !== "tool" ? RGBA.fromInts(40, 40, 40, 255) : undefined
          }
          flexDirection="column"
        >
          {isPendingTool ? (
            <>
              <SpinnerDots
                label={
                  typeof displayContent === "string" ? displayContent : content
                }
                fg="green"
              />
              {/* Args preview for pending tools */}
              {argsPreview && (
                <text fg={RGBA.fromInts(120, 120, 120, 255)} content={`  ${argsPreview}`} />
              )}
              {/* Streaming logs for pending tools */}
              {streamingLogs.length > 0 && (
                <box flexDirection="column" marginTop={0} paddingLeft={2}>
                  {streamingLogs.slice(-3).map((log, idx) => (
                    <text
                      key={idx}
                      fg={RGBA.fromInts(100, 100, 100, 255)}
                      content={log.length > 100 ? log.slice(0, 100) + "…" : log}
                    />
                  ))}
                </box>
              )}
            </>
          ) : (
            <>
              {/* Completed/error tool indicator */}
              {message.role === "tool" && (
                <box flexDirection="row" gap={1}>
                  <text fg={isErrorTool ? "red" : "green"}>
                    {isErrorTool ? "✗" : "✓"}
                  </text>
                  <text fg="white" content={displayContent} />
                </box>
              )}
              {message.role !== "tool" && (
                <text fg="white" content={displayContent} />
              )}
              {/* Args preview for completed tools */}
              {message.role === "tool" && argsPreview && (
                <text fg={RGBA.fromInts(120, 120, 120, 255)} content={`  ${argsPreview}`} />
              )}
            </>
          )}
        </box>
        {message.role === "user" && (
          <box
            width={0}
            borderStyle="heavy"
            border={["left"]}
            borderColor={RGBA.fromInts(30, 30, 30, 255)}
          />
        )}
      </box>
      <ToolDetails message={message} />
    </box>
  );
});

function ToolDetails({ message }: { message: DisplayMessage }) {
  const [showArgs, setShowArgs] = useState(false);
  const [showResult, setShowResult] = useState(false);

  if (message.role !== "tool") {
    return null;
  }

  const hasArgs = "args" in message && message.args;
  const hasResult = "result" in message && message.result !== undefined;

  if (!hasArgs && !hasResult) {
    return null;
  }

  // Format result for display (truncate if too long)
  const formatResult = (result: unknown): string => {
    try {
      const str = JSON.stringify(result, null, 2);
      // Truncate very long results
      if (str.length > 2000) {
        return str.substring(0, 2000) + "\n... (truncated)";
      }
      return str;
    } catch {
      return String(result);
    }
  };

  return (
    <box flexDirection="column" gap={1}>
      {hasArgs && (
        <box
          onMouseDown={(e) => {
            e.stopPropagation();
            setShowArgs(!showArgs);
          }}
        >
          <box flexDirection="row" alignItems="center" gap={1}>
            <text fg={RGBA.fromInts(150, 150, 150, 255)}>
              {showArgs ? "▼ Hide args" : "▶ Show args"}
            </text>
          </box>
          {showArgs && (
            <text fg={RGBA.fromInts(180, 180, 180, 255)}>
              {JSON.stringify(message.args, null, 2)}
            </text>
          )}
        </box>
      )}
      {hasResult && (
        <box
          onMouseDown={(e) => {
            e.stopPropagation();
            setShowResult(!showResult);
          }}
        >
          <box flexDirection="row" alignItems="center" gap={1}>
            <text fg={RGBA.fromInts(100, 200, 100, 255)}>
              {showResult ? "▼ Hide output" : "▶ Show output"}
            </text>
          </box>
          {showResult && (
            <text fg={RGBA.fromInts(150, 220, 150, 255)}>
              {formatResult(message.result)}
            </text>
          )}
        </box>
      )}
    </box>
  );
}
