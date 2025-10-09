import { RGBA } from "@opentui/core";
import type { ModelMessage } from "ai";
import { randomUUIDv5 } from "bun";

interface AgentDisplayProps {
  messages: ModelMessage[];
  isStreaming?: boolean;
}

export default function AgentDisplay({
  messages,
  isStreaming = false,
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
      {messages.length === 0 ? (
        <text fg="gray" content="Waiting for messages..." />
      ) : (
        messages.map((message) => <AgentMessage message={message} />)
      )}
      {isStreaming && <text fg="green" content="✴ Thinking..." />}
    </scrollbox>
  );
}

function AgentMessage({ message }: { message: ModelMessage }) {
  let content = "";

  if (typeof message.content === "string") {
    content = message.content;
  } else if (Array.isArray(message.content)) {
    // Handle array of content parts
    content = message.content
      .map((part: any) => {
        if (typeof part === "string") return part;
        if (part.type === "text" && part.text) return part.text;
        if (part.type === "tool-call") {
          return `🔧 Tool: ${part.toolName}\nArgs: ${JSON.stringify(
            part.args,
            null,
            2
          )}`;
        }
        if (part.type === "tool-result") {
          return `✓ Result: ${JSON.stringify(part.result, null, 2)}`;
        }
        // Fallback for unknown content types
        return JSON.stringify(part, null, 2);
      })
      .join("\n\n");
  } else if (message.content && typeof message.content === "object") {
    content = JSON.stringify(message.content, null, 2);
  } else {
    content = "(empty message)";
  }

  return (
    <box
      key={`${message.role}-${Math.random()}`}
      flexDirection="column"
      width="100%"
      gap={1}
      alignItems={message.role === "user" ? "flex-end" : "flex-start"}
    >
      <text
        fg="green"
        content={message.role === "user" ? "→ User" : "← Assistant"}
      />
      <box flexDirection="row" gap={1}>
        {message.role === "assistant" && (
          <box width={1} backgroundColor={RGBA.fromInts(30, 30, 30, 255)} />
        )}
        <box padding={1} backgroundColor={RGBA.fromInts(40, 40, 40, 255)}>
          <text fg="white" content={content || "(no content)"} />
        </box>
        {message.role === "user" && (
          <box width={1} backgroundColor={RGBA.fromInts(30, 30, 30, 255)} />
        )}
      </box>
    </box>
  );
}
