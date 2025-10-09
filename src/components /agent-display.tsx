import type { ModelMessage } from "ai";

interface AgentDisplayProps {
  messages: ModelMessage[];
  isStreaming?: boolean;
}

export default function AgentDisplay({
  messages,
  isStreaming = false,
}: AgentDisplayProps) {
  console.log("AgentDisplay render - message count:", messages.length);
  messages.forEach((msg, idx) => {
    console.log(
      `Message ${idx}:`,
      msg.role,
      "Content type:",
      typeof msg.content,
      "Content:",
      msg.content
    );
  });

  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      padding={2}
      gap={1}
      flexGrow={1}
    >
      <text fg="cyan">Agent Output</text>
      <box
        flexDirection="column"
        gap={1}
        flexGrow={1}
        style={{ overflow: "scroll" }}
      >
        {messages.length === 0 ? (
          <text fg="gray">Waiting for messages...</text>
        ) : (
          messages.map((message, index) => {
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

            return (
              <box key={index} flexDirection="column" width="100%">
                <text fg="green">
                  {message.role === "user" ? "→ User" : "← Assistant"}
                </text>
                <text fg="white">{content}</text>
              </box>
            );
          })
        )}
        {isStreaming && <text fg="yellow">● Streaming...</text>}
      </box>
    </box>
  );
}
