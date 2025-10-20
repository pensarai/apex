import {
  RGBA,
  TextAttributes,
  StyledText,
  type TextChunk,
} from "@opentui/core";
import { SpinnerDots } from "./sprites";
import type { Message, ToolMessage } from "../../core/messages";
import { useState, useMemo, memo, useRef, useEffect, useCallback } from "react";
import { marked } from "marked";
import type { Subagent } from "./hooks/pentestAgent";

interface AgentDisplayProps {
  key?: string;
  messages: Message[];
  isStreaming?: boolean;
  children?: React.ReactNode;
  subagents?: Subagent[];
  paddingLeft?: number;
  paddingRight?: number;
}

// Utility function to convert markdown to StyledText
function markdownToStyledText(content: string): StyledText {
  try {
    const tokens = marked.lexer(content);
    const chunks: TextChunk[] = [];

    function processInlineTokens(
      inlineTokens: any[],
      defaultAttrs: number = 0
    ): void {
      for (const token of inlineTokens) {
        if (token.type === "text") {
          chunks.push({
            __isChunk: true,
            text: token.text,
            attributes: defaultAttrs,
          });
        } else if (token.type === "strong") {
          processInlineTokens(token.tokens, defaultAttrs | TextAttributes.BOLD);
        } else if (token.type === "em") {
          processInlineTokens(
            token.tokens,
            defaultAttrs | TextAttributes.ITALIC
          );
        } else if (token.type === "codespan") {
          chunks.push({
            __isChunk: true,
            text: token.text,
            fg: RGBA.fromInts(100, 255, 100, 255), // green for code
            attributes: defaultAttrs,
          });
        } else if (token.type === "link") {
          chunks.push({
            __isChunk: true,
            text: token.text,
            fg: RGBA.fromInts(100, 200, 255, 255), // cyan for links
            attributes: defaultAttrs | TextAttributes.UNDERLINE,
          });
        } else if (token.type === "br") {
          chunks.push({
            __isChunk: true,
            text: "\n",
            attributes: defaultAttrs,
          });
        } else if (token.tokens) {
          processInlineTokens(token.tokens, defaultAttrs);
        }
      }
    }

    for (const token of tokens) {
      if (token.type === "paragraph") {
        if (token.tokens) processInlineTokens(token.tokens);
        chunks.push({ __isChunk: true, text: "\n\n", attributes: 0 });
      } else if (token.type === "heading") {
        if (token.tokens)
          processInlineTokens(token.tokens, TextAttributes.BOLD);
        chunks.push({ __isChunk: true, text: "\n\n", attributes: 0 });
      } else if (token.type === "list") {
        for (const item of token.items) {
          chunks.push({
            __isChunk: true,
            text: token.ordered ? `${item.task ? "☐ " : "• "}` : "• ",
            attributes: 0,
          });
          processInlineTokens(item.tokens[0]?.tokens || []);
          chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
        }
        chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
      } else if (token.type === "code") {
        chunks.push({
          __isChunk: true,
          text: token.text + "\n\n",
          fg: RGBA.fromInts(100, 255, 100, 255), // green for code blocks
          attributes: 0,
        });
      } else if (token.type === "blockquote") {
        if (token.tokens) processInlineTokens(token.tokens);
        chunks.push({ __isChunk: true, text: "\n\n", attributes: 0 });
      } else if (token.type === "space") {
        chunks.push({ __isChunk: true, text: "\n", attributes: 0 });
      }
    }

    // Remove trailing newlines from the last chunk
    if (chunks.length > 0) {
      const lastChunk = chunks[chunks.length - 1];
      if (lastChunk && lastChunk.text) {
        lastChunk.text = lastChunk.text.trimEnd();
        // Remove the chunk entirely if it's now empty
        if (lastChunk.text === "") {
          chunks.pop();
        }
      }
    }

    return new StyledText(chunks);
  } catch (error) {
    // Fallback to plain text if parsing fails
    return new StyledText([
      {
        __isChunk: true,
        text: content,
        attributes: 0,
      },
    ]);
  }
}

export default function AgentDisplay({
  key,
  messages,
  isStreaming = false,
  children,
  subagents,
  paddingLeft = 8,
  paddingRight = 8,
}: AgentDisplayProps) {
  const scrollboxRef = useRef<any>(null);

  const [openSubagents, setOpenSubagents] = useState<Set<string>>(new Set());

  const toggleSubagent = useCallback((id: string) => {
    setOpenSubagents(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  // Separate rendering: sort messages and subagents independently
  const sortedMessages = useMemo(
    () => [...messages].sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime()),
    [messages]
  );

  const sortedSubagents = useMemo(
    () => [...(subagents ?? [])].sort((a, b) => {
      // Primary: sort by createdAt
      const timeDiff = a.createdAt.getTime() - b.createdAt.getTime();
      if (timeDiff !== 0) return timeDiff;

      // Tie-breaker: sort by ID
      return a.id.localeCompare(b.id);
    }),
    [subagents]
  );

  const contentHeight = useMemo(() => {
    let height = sortedMessages.length * 3; 
    sortedSubagents.forEach(sub => {
      height += openSubagents.has(sub.id) ? 38 : 3;
    });
    return height;
  }, [sortedMessages, sortedSubagents, openSubagents]);

  useEffect(() => {
    if (!scrollboxRef.current) return;

    const subagentCount = subagents?.length ?? 0;
    if (subagentCount === 0) return;

    const timer = setTimeout(() => {
      try {
        const scrollElement = scrollboxRef.current;

        if (scrollElement && typeof scrollElement.scrollTo === 'function') {
          scrollElement.scrollTo(0, 999999); // Scroll to maximum Y position
        } else if (scrollElement && scrollElement._viewport) {
          const viewportHeight = 50; 
          const maxScroll = Math.max(0, contentHeight - viewportHeight);

          if (scrollElement._viewport.scrollY > maxScroll) {
            scrollElement._viewport.scrollY = maxScroll;
          } else {
            scrollElement._viewport.scrollY = 999999;
          }
        }
      } catch (e) {}
    }, 10);

    return () => clearTimeout(timer);
  }, [subagents?.length, contentHeight]); 

  return (
    <scrollbox
      ref={scrollboxRef}
      style={{
        rootOptions: {
          width: "100%",
          maxWidth: "100%",
          flexGrow: 1,
          flexShrink: 1,
          overflow: "hidden",
        },
        wrapperOptions: {
          overflow: "hidden",
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
      focused
    >
      {/* Render messages first with stable keys */}
      {sortedMessages.map((message) => {
        // Generate stable key without index dependency
        const messageKey =
          message.role === "tool" && "toolCallId" in message
            ? `tool-${(message as ToolMessage).toolCallId}`
            : `msg-${message.role}-${message.createdAt.getTime()}`;

        return (
          <box key={messageKey}>
            <AgentMessage message={message} />
          </box>
        );
      })}

      {/* Render subagents separately with guaranteed stable keys */}
      {sortedSubagents.map((subagent) => (
        <box key={`subagent-${subagent.id}`}>
          <SubAgentDisplay
            subagent={subagent}
            open={openSubagents.has(subagent.id)}
            onToggle={() => toggleSubagent(subagent.id)}
          />
        </box>
      ))}

      {isStreaming && (
        <box flexDirection="row" alignItems="center">
          <SpinnerDots label="Thinking..." fg="green" />
        </box>
      )}

      {children}
    </scrollbox>
  );
}

const SubAgentDisplay = memo(({
  subagent,
  open,
  onToggle
}: {
  subagent: Subagent;
  open: boolean;
  onToggle: () => void;
}) => {
  return (
    <box
      width="100%"
      border={true}
      borderColor="green"
      backgroundColor={RGBA.fromInts(10, 10, 10, 255)}
      flexDirection="column"
    >
      <box
        flexDirection="row"
        alignItems="center"
        gap={1}
        onMouseDown={onToggle}
        padding={1}
        flexShrink={0}
      >
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
      {/* Content constrained to fixed height so scrollbox can't capture parent events */}
      {open && (
        <box
          height={35}
          width="100%"
          overflow="hidden"
          flexShrink={0}
        >
          <AgentDisplay
            paddingLeft={2}
            paddingRight={2}
            messages={subagent.messages}
          />
        </box>
      )}
    </box>
  );
}, (prevProps, nextProps) => {
  // Re-render if subagent data OR open state changes
  return prevProps.subagent === nextProps.subagent &&
         prevProps.open === nextProps.open;
});

function AgentMessage({ message }: { message: Message }) {
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
    message.role === "tool" && (message as ToolMessage).status === "pending";

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
          padding={message.role !== "tool" ? 1 : 0}
          backgroundColor={
            message.role !== "tool" ? RGBA.fromInts(40, 40, 40, 255) : undefined
          }
        >
          {isPendingTool ? (
            <SpinnerDots
              label={
                typeof displayContent === "string" ? displayContent : content
              }
              fg="green"
            />
          ) : (
            <text fg="white" content={displayContent} />
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
      <ToolArgs message={message} />
    </box>
  );
}

function ToolArgs({ message }: { message: Message }) {
  const [open, setOpen] = useState(false);
  if (message.role !== "tool" || !("args" in message)) {
    return null;
  }

  const args = message.args;

  return (
    <box onMouseDown={() => setOpen(!open)}>
      <box flexDirection="row" alignItems="center" gap={1}>
        <text>{open ? "▼ Hide args" : "▶ Show args"}</text>
      </box>
      {open && <text>{JSON.stringify(args, null, 2)}</text>}
    </box>
  );
}
