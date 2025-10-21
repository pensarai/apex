#!/usr/bin/env bun
import { render } from "@opentui/react";
import { useState, useEffect } from "react";
import AgentDisplay from "./src/tui/components/agent-display";
import type { Message, ToolMessage } from "./src/core/messages";

/**
 * Test to verify if object mutation is causing tool calls to disappear
 */

function App() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [step, setStep] = useState(0);

  useEffect(() => {
    const allMessages: Message[] = [];

    if (step === 0) {
      // Step 0: Add 3 tool calls (pending)
      console.log("=== STEP 0: Adding 3 pending tool calls ===");
      allMessages.push({
        role: "tool",
        status: "pending",
        toolCallId: "tool-1",
        content: "Tool 1 running",
        args: {},
        toolName: "test1",
        createdAt: new Date(),
      });
      allMessages.push({
        role: "tool",
        status: "pending",
        toolCallId: "tool-2",
        content: "Tool 2 running",
        args: {},
        toolName: "test2",
        createdAt: new Date(),
      });
      allMessages.push({
        role: "tool",
        status: "pending",
        toolCallId: "tool-3",
        content: "Tool 3 running",
        args: {},
        toolName: "test3",
        createdAt: new Date(),
      });

      setMessages([...allMessages]);
      setTimeout(() => setStep(1), 2000);
    } else if (step === 1) {
      // Step 1: Update tool-2 to completed (using MUTATION like the real code)
      console.log("=== STEP 1: Update tool-2 to completed (WITH MUTATION) ===");
      console.log("Watch if tool-1 and tool-3 disappear!");

      const currentMessages = [...messages];
      const index = currentMessages.findIndex(
        (m) => m.role === "tool" && (m as ToolMessage).toolCallId === "tool-2"
      );

      if (index !== -1) {
        // MUTATE the existing object (like the real code does)
        const existingMessage = currentMessages[index] as ToolMessage;
        existingMessage.status = "completed";
        existingMessage.content = "✓ Tool 2 complete";

        console.log(
          "Before setMessages - message count:",
          currentMessages.length
        );
        console.log(
          "Tool IDs:",
          currentMessages
            .filter((m) => m.role === "tool")
            .map((m) => (m as ToolMessage).toolCallId)
        );

        // Set with new array but same mutated objects
        setMessages([...currentMessages]);
      }

      setTimeout(() => setStep(2), 3000);
    } else if (step === 2) {
      console.log("=== STEP 2: Check if all tools still exist ===");
      console.log("Message count:", messages.length);
      console.log(
        "Tool calls:",
        messages
          .filter((m) => m.role === "tool")
          .map((m) => {
            const tool = m as ToolMessage;
            return `${tool.toolCallId}: ${tool.status}`;
          })
      );
    }
  }, [step]);

  const toolCount = messages.filter((m) => m.role === "tool").length;

  return (
    <box flexDirection="column" width="100%" height="100%">
      <box
        padding={1}
        backgroundColor="rgb(40, 40, 40)"
        border={["bottom"]}
        borderColor="green"
      >
        <text fg="green">Mutation Test - Step {step}/2</text>
        <text> | Tool Calls: {toolCount}</text>
      </box>

      <AgentDisplay messages={messages} subagents={[]} isStreaming={step < 2} />

      <box
        padding={1}
        backgroundColor="rgb(40, 40, 40)"
        border={["top"]}
        borderColor="green"
      >
        <text fg="yellow">
          Testing if object mutation causes tool calls to disappear
        </text>
      </box>
    </box>
  );
}

render(<App />, {
  exitOnCtrlC: true,
});

