import { RGBA } from "@opentui/core";
import type { ModelMessage } from "ai";
import { SpinnerDots } from "./sprites";
import type { Message, ToolMessage } from "../../core/messages";

interface AgentDisplayProps {
  messages: Message[];
  isStreaming?: boolean;
  children?: React.ReactNode;
}

export default function AgentDisplay({
  messages,
  isStreaming = false,
  children,
}: AgentDisplayProps) {
  return (
    <scrollbox
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
          paddingLeft: 8,
          paddingRight: 8,
          gap: 1,
          flexGrow: 1,
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
      focused
    >
      {messages.map((message) => (
        <AgentMessage message={message} />
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

  // Check if this is a pending tool message
  const isPendingTool =
    message.role === "tool" && (message as ToolMessage).status === "pending";

  return (
    <box
      key={`${message.role}-${Math.random()}`}
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
      <box flexDirection="row" gap={1}>
        {message.role === "assistant" && (
          <box width={1} backgroundColor={RGBA.fromInts(30, 30, 30, 255)} />
        )}
        <box
          padding={message.role !== "tool" ? 1 : 0}
          backgroundColor={
            message.role !== "tool" ? RGBA.fromInts(40, 40, 40, 255) : undefined
          }
        >
          {isPendingTool ? (
            <SpinnerDots label={content} fg="green" />
          ) : (
            <text fg="white" content={content} />
          )}
        </box>
        {message.role === "user" && (
          <box width={1} backgroundColor={RGBA.fromInts(30, 30, 30, 255)} />
        )}
      </box>
    </box>
  );
}
